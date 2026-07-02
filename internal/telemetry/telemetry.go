// Package telemetry is a minimal OpenTelemetry (OTEL) tracing + structured
// logging shim for the LibreMail bug-report ingest Worker (issue #17).
//
// # Why a hand-rolled shim instead of the OpenTelemetry-Go SDK
//
// The Worker is compiled to Wasm by TinyGo. The full OpenTelemetry-Go SDK
// (go.opentelemetry.io/otel/sdk + the OTLP exporters) pulls in a large
// dependency tree — google.golang.org/protobuf, grpc, reflection-heavy option
// plumbing — that bloats the Wasm binary and does not reliably compile under
// TinyGo. This package instead implements just the slice of OTEL the Worker
// needs: spans, structured log records, and OTLP/HTTP export, using only the
// standard library (net/http, encoding/json, crypto/rand — all already proven
// to compile and run under this project's js/wasm target, see internal/publish
// and internal/crypto). The wire format is OTLP so any OTLP-compatible backend
// can ingest it; only the SDK is hand-rolled, not the protocol.
//
// # Behaviour-preserving by construction
//
// Instrumentation is threaded through context. Instrumented code pulls an
// optional [*Telemetry] from the context with [FromContext]; when it is absent
// (or its exporter is nil) every method is a no-op and the surrounding code
// behaves exactly as it did before. This is what lets the ingest handler, the
// publish job, and the schedule gate be instrumented without changing any of
// their public constructor/function signatures (a hard requirement so parallel
// work that constructs those components via their current APIs keeps compiling).
//
// # Host-testable core
//
// The package carries no build constraints, so it is unit-tested with the
// standard toolchain against [MemoryExporter], an in-memory test exporter. The
// production OTLP/HTTP exporter ([OTLPHTTPExporter]) is exercised in tests
// against an httptest server, never a real backend.
package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// SpanKind mirrors the OTLP span kind enum (opentelemetry-proto SpanKind).
type SpanKind int

const (
	// SpanKindInternal is an internal operation within an application.
	SpanKindInternal SpanKind = 1
	// SpanKindServer is a synchronous inbound (server-side) request span.
	SpanKindServer SpanKind = 2
	// SpanKindClient is a synchronous outbound (client-side) request span.
	SpanKindClient SpanKind = 3
)

// StatusCode mirrors the OTLP Status.StatusCode enum.
type StatusCode int

const (
	// StatusUnset is the default, un-set span status.
	StatusUnset StatusCode = 0
	// StatusOK marks a span the application explicitly considers successful.
	StatusOK StatusCode = 1
	// StatusError marks a span the application considers failed; backends can
	// alert on it.
	StatusError StatusCode = 2
)

// Status is a span's completion status.
type Status struct {
	Code    StatusCode
	Message string
}

// Severity mirrors the OTLP LogRecord SeverityNumber values used by this Worker.
type Severity int

const (
	// SeverityInfo is OTEL severity number 9 (INFO).
	SeverityInfo Severity = 9
	// SeverityWarn is OTEL severity number 13 (WARN).
	SeverityWarn Severity = 13
	// SeverityError is OTEL severity number 17 (ERROR).
	SeverityError Severity = 17
)

// String returns the OTEL severity text ("INFO"/"WARN"/"ERROR").
func (s Severity) String() string {
	switch {
	case s >= SeverityError:
		return "ERROR"
	case s >= SeverityWarn:
		return "WARN"
	default:
		return "INFO"
	}
}

// Alert attribute keys. A telemetry backend can raise an alert on the presence
// of AttrAlert=true (any alert-worthy signal) or on a specific AttrAlertType
// value. These are the hooks issue #17's alerting keys on once an OTLP backend
// is chosen (that choice is TBD); the signals are emitted here so the wiring is
// ready.
const (
	// AttrAlert is a boolean attribute; true marks an alert-worthy signal.
	AttrAlert = "alert"
	// AttrAlertType is a string attribute naming the specific signal, e.g.
	// "publish.cap_hit" or "ingest.error".
	AttrAlertType = "alert.type"
)

// Alert returns the attribute pair that marks a log record or span as an
// alert-worthy signal of the given type. Callers append their own context
// attributes (counts, ids, ...) after it.
func Alert(alertType string) []KeyValue {
	return []KeyValue{Bool(AttrAlert, true), String(AttrAlertType, alertType)}
}

// KeyValue is a single attribute. Value holds one of string, int64, bool, or
// float64; the OTLP exporter maps it to the matching AnyValue variant. Using a
// bare any keeps construction ergonomic and lets tests compare Value directly.
type KeyValue struct {
	Key   string
	Value any
}

// String, Int, Int64, Bool, and Float build typed attributes.
func String(k, v string) KeyValue  { return KeyValue{Key: k, Value: v} }
func Int(k string, v int) KeyValue { return KeyValue{Key: k, Value: int64(v)} }
func Int64(k string, v int64) KeyValue {
	return KeyValue{Key: k, Value: v}
}
func Bool(k string, v bool) KeyValue     { return KeyValue{Key: k, Value: v} }
func Float(k string, v float64) KeyValue { return KeyValue{Key: k, Value: v} }

// TraceID is a 16-byte W3C trace id.
type TraceID [16]byte

// SpanID is an 8-byte W3C span id.
type SpanID [8]byte

// String returns the lowercase hex encoding used by OTLP/JSON.
func (t TraceID) String() string { return hex.EncodeToString(t[:]) }

// String returns the lowercase hex encoding used by OTLP/JSON.
func (s SpanID) String() string { return hex.EncodeToString(s[:]) }

// IsZero reports whether the id is all-zero (unset).
func (t TraceID) IsZero() bool { return t == TraceID{} }

// IsZero reports whether the id is all-zero (unset).
func (s SpanID) IsZero() bool { return s == SpanID{} }

// SpanContext is the trace-correlation identity of a span: its trace id and its
// own span id. It is what rides in context so children can parent themselves and
// log records can correlate to the active span.
type SpanContext struct {
	TraceID TraceID
	SpanID  SpanID
}

// IsValid reports whether both ids are set.
func (sc SpanContext) IsValid() bool { return !sc.TraceID.IsZero() && !sc.SpanID.IsZero() }

// Event is a timestamped event recorded on a span.
type Event struct {
	Name       string
	Time       time.Time
	Attributes []KeyValue
}

// SpanData is a completed span handed to an [Exporter] at End.
type SpanData struct {
	Name         string
	SpanContext  SpanContext
	ParentSpanID SpanID
	Kind         SpanKind
	StartTime    time.Time
	EndTime      time.Time
	Attributes   []KeyValue
	Events       []Event
	Status       Status
}

// LogRecord is a structured log record handed to an [Exporter]. SpanContext is
// the active span at emit time (zero if none), so records correlate to traces.
type LogRecord struct {
	Time        time.Time
	Severity    Severity
	Body        string
	Attributes  []KeyValue
	SpanContext SpanContext
}

// Exporter is the sink for finished spans and log records. The Worker wires
// [OTLPHTTPExporter]; host tests wire [MemoryExporter]. Implementations must be
// safe for concurrent use.
type Exporter interface {
	ExportSpans(ctx context.Context, spans []SpanData) error
	ExportLogs(ctx context.Context, logs []LogRecord) error
	// Shutdown releases any resources; exporters that hold none return nil.
	Shutdown(ctx context.Context) error
}

// Telemetry is the tracer + logger provider. A nil *Telemetry, or one built with
// a nil exporter, is a valid no-op provider: every method is safe to call and
// does nothing, which is the default when OTEL is not configured (the OTLP
// endpoint is TBD, issue #17).
type Telemetry struct {
	exporter Exporter
	now      func() time.Time
	newTrace func() TraceID
	newSpan  func() SpanID
	onErr    func(error)
}

// Option customises a [Telemetry].
type Option func(*Telemetry)

// WithClock injects the time source (tests use a fixed clock for determinism).
func WithClock(now func() time.Time) Option {
	return func(t *Telemetry) {
		if now != nil {
			t.now = now
		}
	}
}

// WithIDGenerator injects the trace/span id sources (tests use counters so ids
// are deterministic). Either function may be nil to keep the default.
func WithIDGenerator(newTrace func() TraceID, newSpan func() SpanID) Option {
	return func(t *Telemetry) {
		if newTrace != nil {
			t.newTrace = newTrace
		}
		if newSpan != nil {
			t.newSpan = newSpan
		}
	}
}

// WithErrorHandler sets a handler for export errors. Telemetry is best-effort:
// export failures never propagate to the instrumented operation, but the Worker
// can wire this to a log so misconfiguration is visible. The default swallows.
func WithErrorHandler(fn func(error)) Option {
	return func(t *Telemetry) {
		if fn != nil {
			t.onErr = fn
		}
	}
}

// New returns a Telemetry exporting to exp. A nil exp yields a no-op provider
// (so callers can always construct one and let configuration decide whether it
// does anything).
func New(exp Exporter, opts ...Option) *Telemetry {
	t := &Telemetry{
		exporter: exp,
		now:      time.Now,
		newTrace: randomTraceID,
		newSpan:  randomSpanID,
		onErr:    func(error) {},
	}
	for _, o := range opts {
		o(t)
	}
	return t
}

// Enabled reports whether this provider will actually record anything. It is
// safe on a nil receiver. Instrumented hot paths can branch on it to skip work
// entirely when telemetry is off.
func (t *Telemetry) Enabled() bool { return t != nil && t.exporter != nil }

// StartSpan begins a span named name and returns a context carrying its
// [SpanContext] (so nested StartSpan calls and log records correlate) plus the
// span. When the provider is disabled it returns ctx unchanged and a nil *Span
// whose methods are all no-ops — so callers need no telemetry-on/off branching.
func (t *Telemetry) StartSpan(ctx context.Context, name string, opts ...SpanOption) (context.Context, *Span) {
	if !t.Enabled() {
		return ctx, nil
	}
	cfg := spanConfig{kind: SpanKindInternal}
	for _, o := range opts {
		o(&cfg)
	}
	parent, _ := SpanContextFromContext(ctx)
	traceID := parent.TraceID
	if traceID.IsZero() {
		traceID = t.newTrace()
	}
	sc := SpanContext{TraceID: traceID, SpanID: t.newSpan()}
	s := &Span{
		tel:    t,
		sc:     sc,
		parent: parent.SpanID,
		name:   name,
		kind:   cfg.kind,
		start:  t.now(),
		attrs:  append([]KeyValue(nil), cfg.attrs...),
	}
	return ContextWithSpanContext(ctx, sc), s
}

// Log emits a structured log record at severity sev, correlated to the active
// span in ctx (if any). It is safe (and a no-op) on a disabled provider.
func (t *Telemetry) Log(ctx context.Context, sev Severity, body string, attrs ...KeyValue) {
	if !t.Enabled() {
		return
	}
	sc, _ := SpanContextFromContext(ctx)
	rec := LogRecord{
		Time:        t.now(),
		Severity:    sev,
		Body:        body,
		Attributes:  append([]KeyValue(nil), attrs...),
		SpanContext: sc,
	}
	if err := t.exporter.ExportLogs(context.Background(), []LogRecord{rec}); err != nil {
		t.onErr(err)
	}
}

// Info, Warn, and Error are severity-specific [Telemetry.Log] wrappers.
func (t *Telemetry) Info(ctx context.Context, body string, attrs ...KeyValue) {
	t.Log(ctx, SeverityInfo, body, attrs...)
}
func (t *Telemetry) Warn(ctx context.Context, body string, attrs ...KeyValue) {
	t.Log(ctx, SeverityWarn, body, attrs...)
}
func (t *Telemetry) Error(ctx context.Context, body string, attrs ...KeyValue) {
	t.Log(ctx, SeverityError, body, attrs...)
}

// SpanOption customises a span at start.
type SpanOption func(*spanConfig)

type spanConfig struct {
	kind  SpanKind
	attrs []KeyValue
}

// WithSpanKind sets the span kind (default [SpanKindInternal]).
func WithSpanKind(k SpanKind) SpanOption {
	return func(c *spanConfig) { c.kind = k }
}

// WithAttributes sets initial span attributes.
func WithAttributes(attrs ...KeyValue) SpanOption {
	return func(c *spanConfig) { c.attrs = append(c.attrs, attrs...) }
}

// Span is an in-progress span. All methods are safe on a nil *Span (the value
// returned by a disabled provider's StartSpan), so instrumented code never needs
// to nil-check.
type Span struct {
	tel    *Telemetry
	sc     SpanContext
	parent SpanID
	name   string
	kind   SpanKind
	start  time.Time

	mu     sync.Mutex
	attrs  []KeyValue
	events []Event
	status Status
	ended  bool
}

// SpanContext returns the span's trace-correlation identity. On a nil span it
// returns the zero value.
func (s *Span) SpanContext() SpanContext {
	if s == nil {
		return SpanContext{}
	}
	return s.sc
}

// SetAttributes adds attributes to the span.
func (s *Span) SetAttributes(attrs ...KeyValue) {
	if s == nil || len(attrs) == 0 {
		return
	}
	s.mu.Lock()
	s.attrs = append(s.attrs, attrs...)
	s.mu.Unlock()
}

// SetStatus sets the span's completion status.
func (s *Span) SetStatus(code StatusCode, msg string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.status = Status{Code: code, Message: msg}
	s.mu.Unlock()
}

// RecordError marks the span failed and records the error message as an event
// and status. A nil error or span is ignored.
func (s *Span) RecordError(err error) {
	if s == nil || err == nil {
		return
	}
	s.AddEvent("exception", String("exception.message", err.Error()))
	s.SetStatus(StatusError, err.Error())
}

// AddEvent records a timestamped event on the span.
func (s *Span) AddEvent(name string, attrs ...KeyValue) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.events = append(s.events, Event{Name: name, Time: s.tel.now(), Attributes: append([]KeyValue(nil), attrs...)})
	s.mu.Unlock()
}

// End finishes the span and exports it. It is idempotent; a nil span is ignored.
func (s *Span) End() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	data := SpanData{
		Name:         s.name,
		SpanContext:  s.sc,
		ParentSpanID: s.parent,
		Kind:         s.kind,
		StartTime:    s.start,
		EndTime:      s.tel.now(),
		Attributes:   append([]KeyValue(nil), s.attrs...),
		Events:       append([]Event(nil), s.events...),
		Status:       s.status,
	}
	s.mu.Unlock()
	if err := s.tel.exporter.ExportSpans(context.Background(), []SpanData{data}); err != nil {
		s.tel.onErr(err)
	}
}

// --- context propagation ---

type telemetryKeyType struct{}
type spanContextKeyType struct{}

var telemetryKey telemetryKeyType
var spanContextKey spanContextKeyType

// NewContext returns a context carrying the telemetry provider. Instrumented
// code deeper in the call tree retrieves it with [FromContext]. Passing a nil
// provider is fine — it yields the no-op behaviour.
func NewContext(ctx context.Context, t *Telemetry) context.Context {
	return context.WithValue(ctx, telemetryKey, t)
}

// FromContext returns the telemetry provider carried by ctx, or nil if none.
// A nil result is a valid no-op provider (all methods are nil-safe).
func FromContext(ctx context.Context) *Telemetry {
	if ctx == nil {
		return nil
	}
	t, _ := ctx.Value(telemetryKey).(*Telemetry)
	return t
}

// ContextWithSpanContext returns a context whose active span is sc (used as the
// parent of the next StartSpan and the correlation id of Log calls).
func ContextWithSpanContext(ctx context.Context, sc SpanContext) context.Context {
	return context.WithValue(ctx, spanContextKey, sc)
}

// SpanContextFromContext returns the active [SpanContext] in ctx.
func SpanContextFromContext(ctx context.Context) (SpanContext, bool) {
	if ctx == nil {
		return SpanContext{}, false
	}
	sc, ok := ctx.Value(spanContextKey).(SpanContext)
	return sc, ok
}

// --- default id generation ---

// randomTraceID / randomSpanID draw ids from crypto/rand. crypto/rand.Read is
// used elsewhere in build-tag-free code that compiles into the Wasm Worker
// (internal/crypto, internal/storage), so it is available under TinyGo/Wasm.
func randomTraceID() TraceID {
	var t TraceID
	_, _ = rand.Read(t[:])
	return t
}

func randomSpanID() SpanID {
	var s SpanID
	_, _ = rand.Read(s[:])
	return s
}
