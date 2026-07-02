package ingest

import (
	"context"
	"sync"
)

// Sink is the storage seam for accepted reports. The ingest endpoint calls
// Store exactly once, with the raw (already size-capped and schema-validated)
// request body, after it has decided to accept a report.
//
// It is intentionally tiny and knows nothing about scrubbing, encryption, or
// R2: those land downstream (PII redaction is #8, encrypted R2 storage is #9).
// Keeping storage behind this interface lets #9 supply a real implementation
// without touching the HTTP-contract code in this package.
type Sink interface {
	// Store persists a raw accepted report body. Returning a non-nil error
	// causes the endpoint to answer 503 (storage unavailable) per the ADR #6
	// response contract; the client is expected to retry with backoff.
	Store(ctx context.Context, raw []byte) error
}

// NopSink is a Sink that accepts and discards every report. It is the default
// wired into the handler until the real storage sink (#9) exists, so the HTTP
// contract (202/400/413/415/405) is fully exercisable today without any
// storage backend.
type NopSink struct{}

// Store discards raw and always succeeds.
func (NopSink) Store(context.Context, []byte) error { return nil }

// MemorySink is an in-memory Sink that retains a copy of every stored report.
// It is intended for tests and local experimentation only: it grows without
// bound and is not safe to use as a production backend.
type MemorySink struct {
	mu      sync.Mutex
	reports [][]byte
}

// Store appends a copy of raw to the in-memory slice.
func (m *MemorySink) Store(_ context.Context, raw []byte) error {
	cp := make([]byte, len(raw))
	copy(cp, raw)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reports = append(m.reports, cp)
	return nil
}

// Reports returns a snapshot copy of the report bodies stored so far.
func (m *MemorySink) Reports() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]byte, len(m.reports))
	copy(out, m.reports)
	return out
}

// Len reports how many reports have been stored.
func (m *MemorySink) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.reports)
}
