//go:build !(js && wasm)

package crypto

// Host AES-256-GCM provider, using Go's standard crypto/aes + crypto/cipher.
//
// This backs `go test`, cmd/devserver, and every non-Wasm build. The Wasm Worker
// build uses gcm_wasm.go (SubtleCrypto) instead, because TinyGo's crypto/aes is
// unreliable (ADR #5). Both paths implement identical AES-256-GCM with a 12-byte
// nonce and 128-bit tag, so they produce byte-identical frames.

import (
	"crypto/aes"
	"crypto/cipher"
)

// hostAEAD implements aead with the standard library.
type hostAEAD struct{}

func init() { primitive = hostAEAD{} }

// newGCM builds an AES-256-GCM AEAD for key. cipher.NewGCM defaults to a 12-byte
// nonce and 16-byte tag, matching the wire format.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key) // 32-byte key selects AES-256
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (hostAEAD) seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	// Seal appends ciphertext||tag; dst nil returns a fresh slice.
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

func (hostAEAD) open(key, nonce, ciphertextAndTag, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertextAndTag, aad)
}
