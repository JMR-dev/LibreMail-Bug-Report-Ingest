package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/crypto"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/ingest"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/scrub"
)

// Sink is the real ingest.Sink. For each accepted report it:
//
//  1. scrubs the raw body (best-effort PII redaction, #8);
//  2. seals the scrubbed bytes with the keyring's active AES-256 key
//     (AES-256-GCM, ADR #5) into a self-describing frame;
//  3. writes the frame to the ObjectStore under a unique, unguessable key.
//
// The store only ever receives ciphertext. Sink is provider-agnostic: paired
// with a MemoryStore it runs on the host (tests, cmd/devserver); paired with an
// R2Store it runs in the Worker. The Worker's keyring loading (from Secrets
// Store) is handled by WorkerSink, which delegates the pipeline to a Sink.
type Sink struct {
	store   ObjectStore
	keyring *crypto.Keyring
	keyFn   func() string
}

// Option customises a Sink.
type Option func(*Sink)

// WithKeyFunc overrides the object-key generator. Intended for tests that need a
// deterministic key; production uses the default random key.
func WithKeyFunc(fn func() string) Option {
	return func(s *Sink) { s.keyFn = fn }
}

// NewSink returns a Sink that stores into store, encrypting under kr's active
// key. kr must be non-nil.
func NewSink(store ObjectStore, kr *crypto.Keyring, opts ...Option) *Sink {
	s := &Sink{store: store, keyring: kr, keyFn: defaultObjectKey}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Store scrubs, encrypts, and persists one accepted report. A non-nil return
// makes the ingest endpoint answer 503 (per ADR #6), so callers should retry.
func (s *Sink) Store(ctx context.Context, raw []byte) error {
	scrubbed := scrub.Scrub(raw)
	sealed, err := crypto.Seal(s.keyring, scrubbed)
	if err != nil {
		return fmt.Errorf("storage: seal: %w", err)
	}
	if err := s.store.Put(ctx, s.keyFn(), sealed); err != nil {
		return fmt.Errorf("storage: put: %w", err)
	}
	return nil
}

// defaultObjectKey builds the key for a freshly accepted report. Reports enter
// the lifecycle (#10) as pending, so the key lives under the pending status
// prefix: reports/pending/<id>. The id is a UTC timestamp (for rough
// lexicographic ordering, convenient for the weekly publish job) plus 80 bits of
// CSPRNG randomness (so ids are unguessable and collision-free within a second),
// and is stable as the report later transitions to published/removed.
func defaultObjectKey() string {
	return ReportKey(StatusPending, newReportID())
}

// newReportID mints a stable, unguessable report id: <utc-ts>-<80-bit-rand>.
func newReportID() string {
	var b [10]byte
	_, _ = rand.Read(b[:])
	ts := time.Now().UTC().Format("20060102T150405")
	return ts + "-" + hex.EncodeToString(b[:])
}

// Sink satisfies the ingest storage seam.
var _ ingest.Sink = (*Sink)(nil)
