package telemetry

import (
	"context"
	"sync"
)

// MemoryExporter is an in-memory [Exporter] for host tests: it retains every
// span and log record it is handed so tests can assert on them. It is safe for
// concurrent use and never fails. It must not be used in production (it grows
// without bound).
type MemoryExporter struct {
	mu    sync.Mutex
	spans []SpanData
	logs  []LogRecord
}

// NewMemoryExporter returns an empty MemoryExporter.
func NewMemoryExporter() *MemoryExporter { return &MemoryExporter{} }

// ExportSpans records spans.
func (m *MemoryExporter) ExportSpans(_ context.Context, spans []SpanData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.spans = append(m.spans, spans...)
	return nil
}

// ExportLogs records log records.
func (m *MemoryExporter) ExportLogs(_ context.Context, logs []LogRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, logs...)
	return nil
}

// Shutdown is a no-op.
func (m *MemoryExporter) Shutdown(context.Context) error { return nil }

// Spans returns a snapshot copy of the exported spans.
func (m *MemoryExporter) Spans() []SpanData {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]SpanData(nil), m.spans...)
}

// Logs returns a snapshot copy of the exported log records.
func (m *MemoryExporter) Logs() []LogRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]LogRecord(nil), m.logs...)
}

// Reset clears all captured spans and logs.
func (m *MemoryExporter) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.spans = nil
	m.logs = nil
}

// SpanByName returns the first captured span with the given name and whether one
// was found. A convenience for assertions.
func (m *MemoryExporter) SpanByName(name string) (SpanData, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.spans {
		if s.Name == name {
			return s, true
		}
	}
	return SpanData{}, false
}

// SpansByName returns all captured spans with the given name, in export order.
func (m *MemoryExporter) SpansByName(name string) []SpanData {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []SpanData
	for _, s := range m.spans {
		if s.Name == name {
			out = append(out, s)
		}
	}
	return out
}

// Attr returns the value of attribute key among attrs and whether it was
// present. It is a helper for tests asserting on span/log attributes.
func Attr(attrs []KeyValue, key string) (any, bool) {
	for _, kv := range attrs {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return nil, false
}

var _ Exporter = (*MemoryExporter)(nil)
