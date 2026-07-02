// Package crypto implements the encrypted-at-rest object format for scrubbed
// LibreMail bug-reports, exactly as fixed by ADR #5
// (docs/decisions/encryption.md): Worker-side AES-256-GCM authenticated
// encryption applied before the object is written to R2, with the key selected
// from a versioned keyring held in Cloudflare Secrets Store.
//
// # Wire format (the contract)
//
// Each object body is one self-describing binary frame:
//
//	offset  size  field
//	------  ----  -------------------------------------------------------------
//	  0      4    magic          = ASCII "LMB1"
//	  4      1    format_version = 0x01
//	  5      2    key_id         = uint16, big-endian (keyring version used)
//	  7     12    nonce          = 96-bit random IV (CSPRNG, unique per object)
//	 19      N    ciphertext     = AES-256-GCM(plaintext)
//	 19+N   16    auth_tag       = 128-bit GCM tag (appended to the ciphertext)
//
// The 7-byte header (magic || version || key_id) is passed to GCM as the
// additional authenticated data (AAD): it is stored in the clear but is
// authenticated, so an attacker cannot flip the key_id, downgrade the format, or
// transplant a body under a different header without failing authentication.
//
// # Provider-independent by design
//
// The framing in this file carries no build constraints and is shared by both
// crypto providers. The raw AES-256-GCM primitive is the only part that differs:
//
//   - gcm_host.go (build tag !(js && wasm)) uses Go's crypto/aes + crypto/cipher.
//     It backs go test, cmd/devserver, and any non-Wasm build.
//   - gcm_wasm.go (build tag js && wasm) uses the Workers runtime's Web Crypto
//     (SubtleCrypto) via syscall/js, per the ADR's TinyGo/Wasm recommendation.
//
// AES-256-GCM is deterministic for a given key, nonce, plaintext and AAD, so both
// providers produce byte-identical frames. The wire format above — not the
// provider — is the contract, which is why an object sealed by one can be opened
// by the other.
package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// Wire-format constants. These are load-bearing: they are the ADR #5 object
// layout and must not change without a format_version bump.
const (
	// Magic is the 4-byte frame magic, ASCII "LMB1".
	Magic = "LMB1"
	// FormatVersion is the current frame format version.
	FormatVersion byte = 0x01
	// KeySize is the AES-256 key length in bytes.
	KeySize = 32
	// NonceSize is the GCM nonce/IV length in bytes (96 bits).
	NonceSize = 12
	// TagSize is the GCM authentication tag length in bytes (128 bits).
	TagSize = 16
	// HeaderSize is the length of the authenticated header (magic||version||key_id).
	HeaderSize = 7

	magicLen    = 4
	keyIDOffset = 5 // magic(4) + version(1)
	nonceOffset = HeaderSize
	bodyOffset  = HeaderSize + NonceSize // 19: start of ciphertext||tag
	// minObjectLen is the smallest possible valid frame: header + nonce + tag,
	// i.e. an empty-plaintext object (ciphertext length 0).
	minObjectLen = HeaderSize + NonceSize + TagSize
)

// Sentinel errors returned by Open. Callers MUST treat any of them as a hard
// failure and never fall back to "publish what we have" (ADR #5, Integrity).
var (
	// ErrMalformed means the object is too short to be a valid frame.
	ErrMalformed = errors.New("crypto: object too short or malformed")
	// ErrBadMagic means the leading 4 bytes are not the "LMB1" magic.
	ErrBadMagic = errors.New("crypto: bad magic")
	// ErrUnsupportedVersion means format_version is not one this build understands.
	ErrUnsupportedVersion = errors.New("crypto: unsupported format version")
	// ErrUnknownKeyID means the frame's key_id is not present in the keyring.
	// Never remove a key version while stored objects still reference it.
	ErrUnknownKeyID = errors.New("crypto: unknown key_id")
	// ErrAuth means GCM authentication failed: the ciphertext, tag, nonce, or
	// authenticated header was modified, or the wrong key was supplied.
	ErrAuth = errors.New("crypto: authentication failed")
)

// aead is the raw AES-256-GCM primitive seam. Exactly one implementation is
// compiled in per build target (host or Wasm); both MUST produce byte-identical
// output for identical inputs.
type aead interface {
	// seal returns ciphertext||tag for plaintext under key+nonce, authenticating
	// aad. key is 32 bytes, nonce is 12 bytes.
	seal(key, nonce, plaintext, aad []byte) ([]byte, error)
	// open returns the plaintext for ciphertextAndTag under key+nonce, verifying
	// aad. A non-nil error means authentication failed.
	open(key, nonce, ciphertextAndTag, aad []byte) ([]byte, error)
}

// primitive is the AES-256-GCM provider, set in the init of the build-tagged
// provider file (gcm_host.go or gcm_wasm.go).
var primitive aead

// Keyring is a parsed, in-memory versioned keyring: a set of AES-256 keys indexed
// by version (the key_id written into each frame) plus the active version used to
// encrypt new objects. Retaining superseded versions is what makes rotation
// data-loss-free (ADR #5, Key rotation).
type Keyring struct {
	active uint16
	keys   map[uint16][]byte
}

// NewKeyring builds a Keyring from an active version and a version->key map. Each
// key must be exactly KeySize (32) bytes, and active must exist in keys. The keys
// are copied, so the caller may reuse its map.
func NewKeyring(active uint16, keys map[uint16][]byte) (*Keyring, error) {
	if len(keys) == 0 {
		return nil, errors.New("crypto: keyring has no keys")
	}
	cp := make(map[uint16][]byte, len(keys))
	for id, k := range keys {
		if len(k) != KeySize {
			return nil, fmt.Errorf("crypto: key %d must be %d bytes, got %d", id, KeySize, len(k))
		}
		dup := make([]byte, KeySize)
		copy(dup, k)
		cp[id] = dup
	}
	if _, ok := cp[active]; !ok {
		return nil, fmt.Errorf("crypto: active version %d not present in keyring", active)
	}
	return &Keyring{active: active, keys: cp}, nil
}

// Active returns the version new objects are encrypted under.
func (kr *Keyring) Active() uint16 { return kr.active }

// activeKey returns the active key and its version.
func (kr *Keyring) activeKey() ([]byte, uint16) {
	return kr.keys[kr.active], kr.active
}

// key returns the key for version id, or ErrUnknownKeyID if the version has been
// retired or was never present.
func (kr *Keyring) key(id uint16) ([]byte, error) {
	k, ok := kr.keys[id]
	if !ok {
		return nil, ErrUnknownKeyID
	}
	return k, nil
}

// keyringJSON is the on-the-wire shape of the Secrets Store keyring secret
// documented in ADR #5: {"active": N, "keys": {"1": "<base64>", ...}}.
type keyringJSON struct {
	Active uint16            `json:"active"`
	Keys   map[string]string `json:"keys"`
}

// ParseKeyring decodes the JSON keyring secret (as stored in Cloudflare Secrets
// Store and read via env.BUGREPORT_ENC_KEYRING.get()) into a Keyring. Each key
// value is standard-base64 of 32 random bytes. This is provider-independent and
// host-testable so the exact same parse runs under go test and in the Worker.
func ParseKeyring(raw []byte) (*Keyring, error) {
	var kj keyringJSON
	if err := json.Unmarshal(raw, &kj); err != nil {
		return nil, fmt.Errorf("crypto: parse keyring: %w", err)
	}
	if len(kj.Keys) == 0 {
		return nil, errors.New("crypto: keyring has no keys")
	}
	keys := make(map[uint16][]byte, len(kj.Keys))
	for verStr, b64 := range kj.Keys {
		ver, err := strconv.ParseUint(verStr, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("crypto: invalid key version %q: %w", verStr, err)
		}
		key, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("crypto: key %s is not valid base64: %w", verStr, err)
		}
		keys[uint16(ver)] = key
	}
	return NewKeyring(kj.Active, keys)
}

// GenerateKey returns a fresh 32-byte AES-256 key drawn from the CSPRNG. It is
// used by cmd/devserver (a throwaway per-run key) and by tests.
func GenerateKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("crypto: generate key: %w", err)
	}
	return k, nil
}

// header builds the 7-byte authenticated header for a key_id.
func header(keyID uint16) []byte {
	h := make([]byte, HeaderSize)
	copy(h, Magic)
	h[magicLen] = FormatVersion
	binary.BigEndian.PutUint16(h[keyIDOffset:HeaderSize], keyID)
	return h
}

// Seal scrubbed plaintext into a complete R2 object frame using the keyring's
// active key and a fresh random nonce, per ADR #5. The returned bytes are the
// full self-describing frame and are safe to write straight to R2; only
// ciphertext ever leaves this function.
func Seal(kr *Keyring, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce: %w", err)
	}
	return sealWithNonce(kr, plaintext, nonce)
}

// sealWithNonce is Seal with a caller-supplied nonce. It exists so tests can pin
// the nonce for known-answer vectors; production code must use Seal, which draws
// a unique random nonce per object (never reuse a nonce under one key).
func sealWithNonce(kr *Keyring, plaintext, nonce []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("crypto: nonce must be %d bytes, got %d", NonceSize, len(nonce))
	}
	key, keyID := kr.activeKey()
	hdr := header(keyID)
	ctTag, err := primitive.seal(key, nonce, plaintext, hdr)
	if err != nil {
		return nil, fmt.Errorf("crypto: seal: %w", err)
	}
	out := make([]byte, 0, bodyOffset+len(ctTag))
	out = append(out, hdr...)
	out = append(out, nonce...)
	out = append(out, ctTag...)
	return out, nil
}

// Open parses and decrypts an R2 object frame, selecting the key by the frame's
// key_id and verifying the authenticated header. Any tampering (to ciphertext,
// tag, nonce, or header) or a wrong/absent key yields an error; callers must
// treat that as a hard failure.
func Open(kr *Keyring, object []byte) ([]byte, error) {
	if len(object) < minObjectLen {
		return nil, ErrMalformed
	}
	if string(object[:magicLen]) != Magic {
		return nil, ErrBadMagic
	}
	if object[magicLen] != FormatVersion {
		return nil, ErrUnsupportedVersion
	}
	keyID := binary.BigEndian.Uint16(object[keyIDOffset:HeaderSize])
	hdr := object[:HeaderSize]
	nonce := object[nonceOffset:bodyOffset]
	ctTag := object[bodyOffset:]

	key, err := kr.key(keyID)
	if err != nil {
		return nil, err
	}
	plaintext, err := primitive.open(key, nonce, ctTag, hdr)
	if err != nil {
		return nil, ErrAuth
	}
	return plaintext, nil
}

// KeyID reads the key_id from an object frame without decrypting it. It is useful
// for ops/metrics; the value is authenticated only when Open succeeds, so do not
// trust it for anything security-sensitive on its own.
func KeyID(object []byte) (uint16, error) {
	if len(object) < HeaderSize {
		return 0, ErrMalformed
	}
	if string(object[:magicLen]) != Magic {
		return 0, ErrBadMagic
	}
	return binary.BigEndian.Uint16(object[keyIDOffset:HeaderSize]), nil
}
