//go:build js && wasm

package crypto

// Wasm AES-256-GCM provider, using the Workers runtime's Web Crypto
// (SubtleCrypto) through syscall/js.
//
// Per ADR #5, TinyGo's crypto/aes is not reliable in Wasm, so the Worker build
// performs AES-256-GCM via crypto.subtle.encrypt / crypto.subtle.decrypt with
// { name: "AES-GCM", iv, additionalData, tagLength: 128 }. This produces exactly
// the same ciphertext||tag as the host crypto/cipher provider (gcm_host.go), so
// the on-disk wire format in frame.go is identical regardless of provider.
//
// This file is compiled only into the js/wasm Worker (it is excluded from host
// builds and `go test`); CI's TinyGo build is what exercises it.

import (
	"fmt"
	"syscall/js"
)

// subtleAEAD implements aead via SubtleCrypto.
type subtleAEAD struct{}

func init() { primitive = subtleAEAD{} }

// subtle returns the crypto.subtle object, fetched lazily to avoid any
// init-ordering assumptions about JS globals.
func subtle() js.Value {
	return js.Global().Get("crypto").Get("subtle")
}

// toUint8Array copies b into a new JS Uint8Array.
func toUint8Array(b []byte) js.Value {
	ua := js.Global().Get("Uint8Array").New(len(b))
	if len(b) > 0 {
		js.CopyBytesToJS(ua, b)
	}
	return ua
}

// bytesFromArrayBuffer copies an ArrayBuffer (the result of encrypt/decrypt) into
// a Go byte slice.
func bytesFromArrayBuffer(buf js.Value) []byte {
	ua := js.Global().Get("Uint8Array").New(buf)
	out := make([]byte, ua.Get("length").Int())
	if len(out) > 0 {
		js.CopyBytesToGo(out, ua)
	}
	return out
}

// gcmParams builds the AesGcmParams object for encrypt/decrypt.
func gcmParams(nonce, aad []byte) js.Value {
	p := js.Global().Get("Object").New()
	p.Set("name", "AES-GCM")
	p.Set("iv", toUint8Array(nonce))
	p.Set("additionalData", toUint8Array(aad))
	p.Set("tagLength", 128)
	return p
}

// importKey imports a raw 32-byte key as a non-extractable AES-GCM CryptoKey
// usable for both encrypt and decrypt.
func importKey(key []byte) (js.Value, error) {
	algo := js.Global().Get("Object").New()
	algo.Set("name", "AES-GCM")
	usages := js.Global().Get("Array").New()
	usages.Call("push", "encrypt")
	usages.Call("push", "decrypt")
	return await(subtle().Call("importKey", "raw", toUint8Array(key), algo, false, usages))
}

func (subtleAEAD) seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	ck, err := importKey(key)
	if err != nil {
		return nil, err
	}
	res, err := await(subtle().Call("encrypt", gcmParams(nonce, aad), ck, toUint8Array(plaintext)))
	if err != nil {
		return nil, err
	}
	return bytesFromArrayBuffer(res), nil
}

func (subtleAEAD) open(key, nonce, ciphertextAndTag, aad []byte) ([]byte, error) {
	ck, err := importKey(key)
	if err != nil {
		return nil, err
	}
	// A tampered ciphertext/tag/nonce/aad causes SubtleCrypto to reject; await
	// surfaces that as an error, which Open maps to ErrAuth.
	res, err := await(subtle().Call("decrypt", gcmParams(nonce, aad), ck, toUint8Array(ciphertextAndTag)))
	if err != nil {
		return nil, err
	}
	return bytesFromArrayBuffer(res), nil
}

// await resolves a JS Promise synchronously from the calling goroutine. It is
// safe because the Worker runs each request handler in its own goroutine (see
// syumai/workers), so parking here lets the JS event loop run the settling
// callback. Mirrors syumai/workers' internal AwaitPromise.
func await(p js.Value) (js.Value, error) {
	resCh := make(chan js.Value, 1)
	errCh := make(chan error, 1)
	var then, catch js.Func
	then = js.FuncOf(func(_ js.Value, args []js.Value) any {
		then.Release()
		catch.Release()
		v := js.Undefined()
		if len(args) > 0 {
			v = args[0]
		}
		resCh <- v
		return js.Undefined()
	})
	catch = js.FuncOf(func(_ js.Value, args []js.Value) any {
		then.Release()
		catch.Release()
		msg := "unknown error"
		if len(args) > 0 {
			msg = args[0].Call("toString").String()
		}
		errCh <- fmt.Errorf("crypto/subtle: %s", msg)
		return js.Undefined()
	})
	p.Call("then", then).Call("catch", catch)
	select {
	case v := <-resCh:
		return v, nil
	case err := <-errCh:
		return js.Value{}, err
	}
}
