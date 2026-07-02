package storage

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/crypto"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/scrub"
)

// ghToken is a GitHub-token-shaped test value, assembled at runtime so the
// contiguous token pattern never appears as a literal in source (secret scanners
// flag test tokens on sight; internal/scrub/scrub_test.go uses the same trick for
// a GitLab PAT).
var ghToken = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"

// rawReport is a realistic raw body carrying several kinds of PII plus some
// non-sensitive structure that must survive scrubbing.
var rawReport = `{"appVersion":"1.4.2","platform":"android",` +
	`"report":"crash when syncing. contact alice@example.com. ` +
	`token=` + ghToken + ` from 203.0.113.7"}`

// piiSubstrings are values that must never survive scrubbing, and must never be
// readable in the stored ciphertext.
var piiSubstrings = []string{
	"alice@example.com",
	ghToken,
	"203.0.113.7",
}

func mustKeyring(t *testing.T) *crypto.Keyring {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kr, err := crypto.NewKeyring(1, map[uint16][]byte{1: key})
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return kr
}

func TestMemoryStorePutGet(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()

	if _, err := m.Get(ctx, "absent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get(absent) err = %v, want ErrNotFound", err)
	}

	want := []byte("some bytes")
	if err := m.Put(ctx, "k", want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := m.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Get = %q, want %q", got, want)
	}
	// Stored copy must be independent of the caller's slice.
	want[0] = 'X'
	if again, _ := m.Get(ctx, "k"); again[0] == 'X' {
		t.Error("MemoryStore did not copy the value on Put")
	}
	if m.Len() != 1 {
		t.Errorf("Len = %d, want 1", m.Len())
	}
}

// TestSinkFullPath is the end-to-end acceptance: raw report -> scrubbed ->
// encrypted -> stored, and reading it back REQUIRES the key and yields the
// scrubbed (not raw) content.
func TestSinkFullPath(t *testing.T) {
	ctx := context.Background()
	kr := mustKeyring(t)
	store := NewMemoryStore()
	sink := NewSink(store, kr)

	if err := sink.Store(ctx, []byte(rawReport)); err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Exactly one object, under a reports/ key.
	keys := store.Keys()
	if len(keys) != 1 {
		t.Fatalf("stored %d objects, want 1", len(keys))
	}
	if !strings.HasPrefix(keys[0], objectKeyPrefix) {
		t.Errorf("object key %q lacks prefix %q", keys[0], objectKeyPrefix)
	}

	stored, err := store.Get(ctx, keys[0])
	if err != nil {
		t.Fatalf("Get stored: %v", err)
	}

	// The stored bytes are a sealed frame, not the raw or scrubbed plaintext.
	scrubbed := scrub.Scrub([]byte(rawReport))
	if bytes.Equal(stored, []byte(rawReport)) {
		t.Error("stored object equals the raw body (not encrypted)")
	}
	if bytes.Equal(stored, scrubbed) {
		t.Error("stored object equals the scrubbed plaintext (not encrypted)")
	}
	if string(stored[:4]) != crypto.Magic {
		t.Errorf("stored object magic = %q, want %q", stored[:4], crypto.Magic)
	}

	// The ciphertext must not leak any PII substring in the clear.
	for _, s := range piiSubstrings {
		if bytes.Contains(stored, []byte(s)) {
			t.Errorf("stored ciphertext leaks PII substring %q", s)
		}
	}

	// The object is NOT decryptable without the key.
	otherKR := mustKeyring(t) // different random key, same key_id 1
	if _, err := crypto.Open(otherKR, stored); err == nil {
		t.Error("stored object decrypted with the WRONG key; must require the correct key")
	}

	// With the correct key it yields exactly the scrubbed content.
	opened, err := crypto.Open(kr, stored)
	if err != nil {
		t.Fatalf("Open with correct key: %v", err)
	}
	if !bytes.Equal(opened, scrubbed) {
		t.Errorf("decrypted content != scrubbed content\n got  = %q\n want = %q", opened, scrubbed)
	}

	// The decrypted (scrubbed) content has the PII removed (verify via #8's
	// contract) and carries the redaction placeholders and surviving structure.
	openedStr := string(opened)
	for _, s := range piiSubstrings {
		if strings.Contains(openedStr, s) {
			t.Errorf("decrypted scrubbed content still leaks PII %q", s)
		}
	}
	for _, p := range []string{scrub.PlaceholderEmail, scrub.PlaceholderToken, scrub.PlaceholderIP} {
		if !strings.Contains(openedStr, p) {
			t.Errorf("decrypted scrubbed content missing placeholder %q", p)
		}
	}
	for _, keep := range []string{"crash when syncing", `"appVersion":"1.4.2"`} {
		if !strings.Contains(openedStr, keep) {
			t.Errorf("decrypted scrubbed content dropped non-PII text %q", keep)
		}
	}
}

// failingStore always fails Put, to exercise the Sink's error propagation (which
// drives the ingest 503 path).
type failingStore struct{}

func (failingStore) Put(context.Context, string, []byte) error {
	return errors.New("backend down")
}
func (failingStore) Get(context.Context, string) ([]byte, error) {
	return nil, ErrNotFound
}

func TestSinkStorePutError(t *testing.T) {
	sink := NewSink(failingStore{}, mustKeyring(t))
	if err := sink.Store(context.Background(), []byte(rawReport)); err == nil {
		t.Error("Store returned nil despite a failing backend; want error (drives 503)")
	}
}

func TestSinkUsesDistinctKeys(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	sink := NewSink(store, mustKeyring(t))
	for i := 0; i < 5; i++ {
		if err := sink.Store(ctx, []byte(rawReport)); err != nil {
			t.Fatalf("Store #%d: %v", i, err)
		}
	}
	if store.Len() != 5 {
		t.Errorf("stored %d objects, want 5 distinct keys", store.Len())
	}
}

func TestSinkWithKeyFunc(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	sink := NewSink(store, mustKeyring(t), WithKeyFunc(func() string { return "reports/fixed" }))
	if err := sink.Store(ctx, []byte(rawReport)); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if _, err := store.Get(ctx, "reports/fixed"); err != nil {
		t.Errorf("expected object at fixed key: %v", err)
	}
}
