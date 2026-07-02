package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fixedKey returns a deterministic 32-byte key whose bytes are seed+i, for
// reproducible test vectors (never used outside tests).
func fixedKey(seed byte) []byte {
	k := make([]byte, KeySize)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

func mustKeyring(t *testing.T, active uint16, keys map[uint16][]byte) *Keyring {
	t.Helper()
	kr, err := NewKeyring(active, keys)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return kr
}

// TestSealOpenRoundtrip covers the happy path: Open(Seal(x)) == x, and the
// ciphertext is not the plaintext.
func TestSealOpenRoundtrip(t *testing.T) {
	kr := mustKeyring(t, 1, map[uint16][]byte{1: fixedKey(0)})
	for _, pt := range [][]byte{
		[]byte(""),
		[]byte("x"),
		[]byte("a scrubbed bug report with [REDACTED_EMAIL] inside"),
		bytes.Repeat([]byte("A"), 4096),
	} {
		sealed, err := Seal(kr, pt)
		if err != nil {
			t.Fatalf("Seal(%d bytes): %v", len(pt), err)
		}
		// The sealed frame is never the bare plaintext: it always prepends the
		// 7-byte header + 12-byte nonce and appends the 16-byte GCM tag, so it
		// differs from the plaintext in both length and leading bytes. This is
		// a deterministic check.
		//
		// We deliberately do NOT scan the frame for the plaintext byte-by-byte
		// (the old `bytes.Contains(sealed, pt)`): with a random nonce and
		// ciphertext, a 1-byte plaintext coincides with some frame byte
		// ~11% of the time, which made this test flaky (issue #41).
		// Verbatim-leak coverage lives in TestNoPlaintextLeak, which uses a
		// multi-byte marker where a chance match is negligible.
		if bytes.Equal(sealed, pt) {
			t.Errorf("sealed frame equals the plaintext (len %d)", len(pt))
		}
		got, err := Open(kr, sealed)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Errorf("roundtrip mismatch: got %q want %q", got, pt)
		}
	}
}

// TestWireLayout locks the ADR #5 byte layout of a sealed frame.
func TestWireLayout(t *testing.T) {
	kr := mustKeyring(t, 0xABCD, map[uint16][]byte{0xABCD: fixedKey(3)})
	nonce := bytes.Repeat([]byte{0x5A}, NonceSize)
	pt := []byte("payload")

	frame, err := sealWithNonce(kr, pt, nonce)
	if err != nil {
		t.Fatalf("sealWithNonce: %v", err)
	}

	if got := string(frame[:4]); got != Magic {
		t.Errorf("magic = %q, want %q", got, Magic)
	}
	if frame[4] != FormatVersion {
		t.Errorf("version = 0x%02x, want 0x%02x", frame[4], FormatVersion)
	}
	if id := binary.BigEndian.Uint16(frame[5:7]); id != 0xABCD {
		t.Errorf("key_id = 0x%04x, want 0xABCD", id)
	}
	if got := frame[7:19]; !bytes.Equal(got, nonce) {
		t.Errorf("nonce = %x, want %x", got, nonce)
	}
	// header(7) + nonce(12) + ciphertext(len pt) + tag(16)
	wantLen := HeaderSize + NonceSize + len(pt) + TagSize
	if len(frame) != wantLen {
		t.Errorf("frame len = %d, want %d", len(frame), wantLen)
	}
	if id, err := KeyID(frame); err != nil || id != 0xABCD {
		t.Errorf("KeyID = 0x%04x, err=%v; want 0xABCD, nil", id, err)
	}
}

// TestKnownAnswerVector is a byte-exact format lock. The expected frame was
// computed from Go's standard AES-256-GCM; because AES-256-GCM is deterministic
// and standardised, the Wasm SubtleCrypto provider MUST produce these same bytes
// for the same key+nonce+plaintext+AAD. If this changes, the on-disk format (and
// cross-provider compatibility) changed.
func TestKnownAnswerVector(t *testing.T) {
	key := fixedKey(0) // 0x00,0x01,...,0x1f
	kr := mustKeyring(t, 1, map[uint16][]byte{1: key})
	nonce := make([]byte, NonceSize) // 0x00..0x0b
	for i := range nonce {
		nonce[i] = byte(i)
	}
	pt := []byte("hello world")

	const wantHex = "4c4d4231010001000102030405060708090a0b2f67ba77aac5b574ff2df3f26c5bd31758566cf1bf14ae15f8fd7a"
	frame, err := sealWithNonce(kr, pt, nonce)
	if err != nil {
		t.Fatalf("sealWithNonce: %v", err)
	}
	if got := hex.EncodeToString(frame); got != wantHex {
		t.Errorf("known-answer frame mismatch:\n got  = %s\n want = %s", got, wantHex)
	}
	// And it must still open.
	got, err := Open(kr, frame)
	if err != nil || !bytes.Equal(got, pt) {
		t.Errorf("Open(known frame) = %q, %v; want %q, nil", got, err, pt)
	}
}

// TestSealMatchesStdlibGCM proves the package frames *standard* AES-256-GCM: the
// sealed body equals an independent crypto/cipher GCM computation over the same
// key, nonce, plaintext, and header-as-AAD. This is the provider-independent
// contract the SubtleCrypto build also satisfies.
func TestSealMatchesStdlibGCM(t *testing.T) {
	key := fixedKey(9)
	const keyID = 7
	kr := mustKeyring(t, keyID, map[uint16][]byte{keyID: key})
	nonce := bytes.Repeat([]byte{0x11}, NonceSize)
	pt := []byte("some plaintext to seal")

	got, err := sealWithNonce(kr, pt, nonce)
	if err != nil {
		t.Fatalf("sealWithNonce: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	hdr := append([]byte(Magic), FormatVersion, 0x00, keyID)
	ctTag := gcm.Seal(nil, nonce, pt, hdr)
	want := append(append(append([]byte{}, hdr...), nonce...), ctTag...)

	if !bytes.Equal(got, want) {
		t.Errorf("framing differs from standard AES-256-GCM:\n got  = %x\n want = %x", got, want)
	}
}

// TestOpenWrongKeyFails: an object is not decryptable without the correct key.
func TestOpenWrongKeyFails(t *testing.T) {
	sealKR := mustKeyring(t, 1, map[uint16][]byte{1: fixedKey(0)})
	// Different key material, SAME key_id, so parsing succeeds and only the
	// cryptographic check can reject it.
	wrongKR := mustKeyring(t, 1, map[uint16][]byte{1: fixedKey(100)})

	sealed, err := Seal(sealKR, []byte("secret residual PII"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open(wrongKR, sealed); !errors.Is(err, ErrAuth) {
		t.Errorf("Open with wrong key: err = %v, want ErrAuth", err)
	}
	// Sanity: the right key still works.
	if _, err := Open(sealKR, sealed); err != nil {
		t.Errorf("Open with correct key failed: %v", err)
	}
}

// TestTamperDetection: any modification to the frame makes Open fail (GCM
// authenticates ciphertext, tag, nonce, and the header via AAD).
func TestTamperDetection(t *testing.T) {
	kr := mustKeyring(t, 1, map[uint16][]byte{1: fixedKey(0)})
	sealed, err := Seal(kr, []byte("tamper target payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	cases := []struct {
		name   string
		offset int
		wantIs error // nil means "any non-nil error"
	}{
		{"magic", 0, ErrBadMagic},
		{"version", 4, ErrUnsupportedVersion},
		{"key_id", 6, ErrUnknownKeyID}, // 1 -> some absent version
		{"nonce", nonceOffset, ErrAuth},
		{"ciphertext", bodyOffset, ErrAuth},
		{"tag", len(sealed) - 1, ErrAuth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := append([]byte(nil), sealed...)
			bad[tc.offset] ^= 0xFF
			_, err := Open(kr, bad)
			if err == nil {
				t.Fatalf("tampering %s produced no error", tc.name)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("tampering %s: err = %v, want %v", tc.name, err, tc.wantIs)
			}
		})
	}
}

// TestHeaderIsAuthenticated proves the key_id in the header is bound by AAD: an
// attacker cannot relabel a frame to a different, valid key version.
func TestHeaderIsAuthenticated(t *testing.T) {
	// Keyring holds two versions; seal under version 1.
	kr := mustKeyring(t, 1, map[uint16][]byte{1: fixedKey(0), 2: fixedKey(50)})
	sealed, err := Seal(kr, []byte("bind me"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Rewrite the stored key_id from 1 to 2 (a version that DOES exist).
	relabeled := append([]byte(nil), sealed...)
	binary.BigEndian.PutUint16(relabeled[keyIDOffset:HeaderSize], 2)
	if _, err := Open(kr, relabeled); !errors.Is(err, ErrAuth) {
		t.Errorf("relabeled key_id: err = %v, want ErrAuth (header must be authenticated)", err)
	}
}

// TestRotationRetainsOldKeys: an object sealed under key_id N still opens after
// rotation, as long as the keyring retains version N.
func TestRotationRetainsOldKeys(t *testing.T) {
	key1 := fixedKey(0)
	key2 := fixedKey(50)

	// Before rotation: active = 1.
	before := mustKeyring(t, 1, map[uint16][]byte{1: key1})
	sealed, err := Seal(before, []byte("pre-rotation report"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if id, _ := KeyID(sealed); id != 1 {
		t.Fatalf("sealed key_id = %d, want 1", id)
	}

	// After rotation: active = 2, but version 1 is RETAINED.
	after := mustKeyring(t, 2, map[uint16][]byte{1: key1, 2: key2})
	got, err := Open(after, sealed)
	if err != nil {
		t.Fatalf("Open after rotation (retained key 1): %v", err)
	}
	if want := []byte("pre-rotation report"); !bytes.Equal(got, want) {
		t.Errorf("post-rotation decrypt = %q, want %q", got, want)
	}

	// New writes now use key_id 2.
	sealed2, err := Seal(after, []byte("post-rotation report"))
	if err != nil {
		t.Fatalf("Seal (post-rotation): %v", err)
	}
	if id, _ := KeyID(sealed2); id != 2 {
		t.Errorf("post-rotation sealed key_id = %d, want 2", id)
	}

	// If version 1 is RETIRED (removed), the old object is unrecoverable.
	retired := mustKeyring(t, 2, map[uint16][]byte{2: key2})
	if _, err := Open(retired, sealed); !errors.Is(err, ErrUnknownKeyID) {
		t.Errorf("Open with retired key_id: err = %v, want ErrUnknownKeyID", err)
	}
}

// TestOpenMalformed covers frame-structure rejections.
func TestOpenMalformed(t *testing.T) {
	kr := mustKeyring(t, 1, map[uint16][]byte{1: fixedKey(0)})
	valid, err := Seal(kr, []byte("ok"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tests := []struct {
		name   string
		object []byte
		wantIs error
	}{
		{"empty", nil, ErrMalformed},
		{"too short", valid[:minObjectLen-1], ErrMalformed},
		{"bad magic", func() []byte { b := append([]byte(nil), valid...); b[0] = 'X'; return b }(), ErrBadMagic},
		{"bad version", func() []byte { b := append([]byte(nil), valid...); b[4] = 0x02; return b }(), ErrUnsupportedVersion},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Open(kr, tc.object); !errors.Is(err, tc.wantIs) {
				t.Errorf("Open(%s): err = %v, want %v", tc.name, err, tc.wantIs)
			}
		})
	}
}

// TestParseKeyring parses the ADR #5 Secrets Store JSON shape and roundtrips.
func TestParseKeyring(t *testing.T) {
	key1 := fixedKey(0)
	key2 := fixedKey(200)
	raw := fmt.Sprintf(`{"active":2,"keys":{"1":%q,"2":%q}}`,
		base64.StdEncoding.EncodeToString(key1),
		base64.StdEncoding.EncodeToString(key2))

	kr, err := ParseKeyring([]byte(raw))
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	if kr.Active() != 2 {
		t.Errorf("active = %d, want 2", kr.Active())
	}
	// New objects use active=2; an object made with the parsed keyring opens with
	// an equivalent hand-built keyring, proving the bytes decoded correctly.
	sealed, err := Seal(kr, []byte("via parsed keyring"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	ref := mustKeyring(t, 2, map[uint16][]byte{1: key1, 2: key2})
	if got, err := Open(ref, sealed); err != nil || string(got) != "via parsed keyring" {
		t.Errorf("Open via reference keyring = %q, %v", got, err)
	}
}

func TestParseKeyringErrors(t *testing.T) {
	shortKey := base64.StdEncoding.EncodeToString(make([]byte, 16)) // 16 bytes, not 32
	fullKey := base64.StdEncoding.EncodeToString(fixedKey(0))
	cases := map[string]string{
		"not json":         `{`,
		"no keys":          `{"active":1,"keys":{}}`,
		"bad base64":       `{"active":1,"keys":{"1":"not@@base64"}}`,
		"wrong key length": fmt.Sprintf(`{"active":1,"keys":{"1":%q}}`, shortKey),
		"active absent":    fmt.Sprintf(`{"active":9,"keys":{"1":%q}}`, fullKey),
		"bad version":      fmt.Sprintf(`{"active":1,"keys":{"nope":%q}}`, fullKey),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseKeyring([]byte(raw)); err == nil {
				t.Errorf("ParseKeyring(%s) = nil error, want failure", name)
			}
		})
	}
}

func TestGenerateKey(t *testing.T) {
	a, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(a) != KeySize {
		t.Errorf("key length = %d, want %d", len(a), KeySize)
	}
	b, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("two generated keys are identical; CSPRNG suspect")
	}
}

func TestNewKeyringValidation(t *testing.T) {
	if _, err := NewKeyring(1, nil); err == nil {
		t.Error("empty keyring: want error")
	}
	if _, err := NewKeyring(1, map[uint16][]byte{1: make([]byte, 8)}); err == nil {
		t.Error("short key: want error")
	}
	if _, err := NewKeyring(5, map[uint16][]byte{1: fixedKey(0)}); err == nil {
		t.Error("active not present: want error")
	}
	// NewKeyring must copy its input (mutating the caller's slice must not change
	// the keyring).
	src := fixedKey(0)
	kr := mustKeyring(t, 1, map[uint16][]byte{1: src})
	for i := range src {
		src[i] = 0xEE
	}
	sealed, err := Seal(kr, []byte("copy check"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if got, err := Open(kr, sealed); err != nil || string(got) != "copy check" {
		t.Errorf("keyring did not copy key material: %q, %v", got, err)
	}
}

// TestNoPlaintextLeak is a belt-and-braces check that a sensitive-looking
// plaintext does not appear anywhere in the sealed frame.
func TestNoPlaintextLeak(t *testing.T) {
	kr := mustKeyring(t, 1, map[uint16][]byte{1: fixedKey(0)})
	secret := "MARKER-plaintext-must-not-survive-encryption"
	sealed, err := Seal(kr, []byte("report body: "+secret))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if strings.Contains(string(sealed), secret) {
		t.Error("sealed frame leaks the plaintext secret")
	}
}
