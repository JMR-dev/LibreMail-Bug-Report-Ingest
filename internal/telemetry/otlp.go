package telemetry

// OTLP/HTTP exporter with JSON encoding.
//
// This is the production sink: it POSTs spans and log records to an OTLP/HTTP
// endpoint as JSON (the OTLP-over-HTTP "application/json" encoding, the ProtoJSON
// mapping of opentelemetry-proto). JSON is chosen over protobuf because it needs
// no code generation or protobuf runtime — just encoding/json and net/http, both
// of which compile and run under this project's TinyGo/Wasm Worker target (see
// internal/publish, which drives the GitHub API the same way).
//
// Export is synchronous and best-effort: one POST per span-batch and per
// log-batch. Volumes here are tiny (a handful of spans per ingest request; one
// run plus per-report spans once a week), so batching/async delivery is a
// deliberate non-goal for this first cut — an OTLP collector or a batching
// wrapper can be added later without touching the instrumented code.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Scope identifies the instrumentation scope (the library emitting the
// telemetry) in the OTLP payload.
type Scope struct {
	Name    string
	Version string
}

// OTLPConfig configures an [OTLPHTTPExporter].
type OTLPConfig struct {
	// Endpoint is the base OTLP/HTTP URL, e.g. "https://otlp.example.com". The
	// signal paths "/v1/traces" and "/v1/logs" are appended. This is the value
	// issue #17 leaves TBD; it comes from the OTEL_EXPORTER_OTLP_ENDPOINT Worker
	// var and is never hardcoded.
	Endpoint string
	// Headers are added to every request (e.g. an auth header). In the Worker
	// these come from a secret, never a committed value.
	Headers map[string]string
	// Resource attributes (e.g. service.name) describe the emitting service.
	Resource []KeyValue
	// Scope names the instrumentation library.
	Scope Scope
	// HTTPClient overrides the client (tests inject one; default &http.Client{}).
	HTTPClient *http.Client
	// Timeout bounds each export request when HTTPClient is not supplied
	// (default 10s). Ignored if HTTPClient is set.
	Timeout time.Duration
}

// OTLPHTTPExporter exports spans and logs to an OTLP/HTTP endpoint as JSON.
type OTLPHTTPExporter struct {
	client    *http.Client
	tracesURL string
	logsURL   string
	headers   map[string]string
	resource  []KeyValue
	scope     Scope
}

// NewOTLPHTTPExporter builds an exporter from cfg. It does no I/O.
func NewOTLPHTTPExporter(cfg OTLPConfig) *OTLPHTTPExporter {
	client := cfg.HTTPClient
	if client == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}
	base := strings.TrimRight(cfg.Endpoint, "/")
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	return &OTLPHTTPExporter{
		client:    client,
		tracesURL: base + "/v1/traces",
		logsURL:   base + "/v1/logs",
		headers:   headers,
		resource:  cfg.Resource,
		scope:     cfg.Scope,
	}
}

// ExportSpans POSTs spans to {endpoint}/v1/traces as OTLP/JSON.
func (e *OTLPHTTPExporter) ExportSpans(ctx context.Context, spans []SpanData) error {
	if len(spans) == 0 {
		return nil
	}
	body, err := json.Marshal(e.buildTracesPayload(spans))
	if err != nil {
		return fmt.Errorf("otlp: marshal traces: %w", err)
	}
	return e.post(ctx, e.tracesURL, body)
}

// ExportLogs POSTs logs to {endpoint}/v1/logs as OTLP/JSON.
func (e *OTLPHTTPExporter) ExportLogs(ctx context.Context, logs []LogRecord) error {
	if len(logs) == 0 {
		return nil
	}
	body, err := json.Marshal(e.buildLogsPayload(logs))
	if err != nil {
		return fmt.Errorf("otlp: marshal logs: %w", err)
	}
	return e.post(ctx, e.logsURL, body)
}

// Shutdown is a no-op; the exporter holds no long-lived resources.
func (e *OTLPHTTPExporter) Shutdown(context.Context) error { return nil }

// post sends body to url with the configured headers and returns an error on a
// transport failure or a non-2xx status.
func (e *OTLPHTTPExporter) post(ctx context.Context, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("otlp: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("otlp: post %s: %w", url, err)
	}
	defer resp.Body.Close()
	// Drain so the connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("otlp: post %s: unexpected status %d", url, resp.StatusCode)
	}
	return nil
}

// --- OTLP/JSON wire types (ProtoJSON mapping of opentelemetry-proto) ---

type otlpTracesPayload struct {
	ResourceSpans []otlpResourceSpans `json:"resourceSpans"`
}

type otlpResourceSpans struct {
	Resource   otlpResource     `json:"resource"`
	ScopeSpans []otlpScopeSpans `json:"scopeSpans"`
}

type otlpScopeSpans struct {
	Scope otlpScope  `json:"scope"`
	Spans []otlpSpan `json:"spans"`
}

type otlpLogsPayload struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

type otlpResourceLogs struct {
	Resource  otlpResource    `json:"resource"`
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

type otlpScopeLogs struct {
	Scope      otlpScope       `json:"scope"`
	LogRecords []otlpLogRecord `json:"logRecords"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes,omitempty"`
}

type otlpScope struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

type otlpSpan struct {
	TraceID           string         `json:"traceId"`
	SpanID            string         `json:"spanId"`
	ParentSpanID      string         `json:"parentSpanId,omitempty"`
	Name              string         `json:"name"`
	Kind              int            `json:"kind,omitempty"`
	StartTimeUnixNano string         `json:"startTimeUnixNano"`
	EndTimeUnixNano   string         `json:"endTimeUnixNano"`
	Attributes        []otlpKeyValue `json:"attributes,omitempty"`
	Events            []otlpEvent    `json:"events,omitempty"`
	Status            *otlpStatus    `json:"status,omitempty"`
}

type otlpEvent struct {
	TimeUnixNano string         `json:"timeUnixNano"`
	Name         string         `json:"name"`
	Attributes   []otlpKeyValue `json:"attributes,omitempty"`
}

type otlpStatus struct {
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
}

type otlpLogRecord struct {
	TimeUnixNano   string         `json:"timeUnixNano"`
	SeverityNumber int            `json:"severityNumber,omitempty"`
	SeverityText   string         `json:"severityText,omitempty"`
	Body           *otlpAnyValue  `json:"body,omitempty"`
	Attributes     []otlpKeyValue `json:"attributes,omitempty"`
	TraceID        string         `json:"traceId,omitempty"`
	SpanID         string         `json:"spanId,omitempty"`
}

type otlpKeyValue struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

// otlpAnyValue is the OTLP AnyValue. Exactly one field is non-nil. Per proto3
// JSON, int64 is encoded as a string.
type otlpAnyValue struct {
	StringValue *string  `json:"stringValue,omitempty"`
	BoolValue   *bool    `json:"boolValue,omitempty"`
	IntValue    *string  `json:"intValue,omitempty"`
	DoubleValue *float64 `json:"doubleValue,omitempty"`
}

func (e *OTLPHTTPExporter) buildTracesPayload(spans []SpanData) otlpTracesPayload {
	out := make([]otlpSpan, 0, len(spans))
	for _, s := range spans {
		os := otlpSpan{
			TraceID:           s.SpanContext.TraceID.String(),
			SpanID:            s.SpanContext.SpanID.String(),
			Name:              s.Name,
			Kind:              int(s.Kind),
			StartTimeUnixNano: nanos(s.StartTime),
			EndTimeUnixNano:   nanos(s.EndTime),
			Attributes:        toOTLPAttrs(s.Attributes),
		}
		if !s.ParentSpanID.IsZero() {
			os.ParentSpanID = s.ParentSpanID.String()
		}
		if len(s.Events) > 0 {
			os.Events = make([]otlpEvent, 0, len(s.Events))
			for _, ev := range s.Events {
				os.Events = append(os.Events, otlpEvent{
					TimeUnixNano: nanos(ev.Time),
					Name:         ev.Name,
					Attributes:   toOTLPAttrs(ev.Attributes),
				})
			}
		}
		if s.Status.Code != StatusUnset || s.Status.Message != "" {
			os.Status = &otlpStatus{Code: int(s.Status.Code), Message: s.Status.Message}
		}
		out = append(out, os)
	}
	return otlpTracesPayload{ResourceSpans: []otlpResourceSpans{{
		Resource:   otlpResource{Attributes: toOTLPAttrs(e.resource)},
		ScopeSpans: []otlpScopeSpans{{Scope: e.otlpScope(), Spans: out}},
	}}}
}

func (e *OTLPHTTPExporter) buildLogsPayload(logs []LogRecord) otlpLogsPayload {
	out := make([]otlpLogRecord, 0, len(logs))
	for _, l := range logs {
		body := l.Body
		rec := otlpLogRecord{
			TimeUnixNano:   nanos(l.Time),
			SeverityNumber: int(l.Severity),
			SeverityText:   l.Severity.String(),
			Body:           &otlpAnyValue{StringValue: &body},
			Attributes:     toOTLPAttrs(l.Attributes),
		}
		if l.SpanContext.IsValid() {
			rec.TraceID = l.SpanContext.TraceID.String()
			rec.SpanID = l.SpanContext.SpanID.String()
		}
		out = append(out, rec)
	}
	return otlpLogsPayload{ResourceLogs: []otlpResourceLogs{{
		Resource:  otlpResource{Attributes: toOTLPAttrs(e.resource)},
		ScopeLogs: []otlpScopeLogs{{Scope: e.otlpScope(), LogRecords: out}},
	}}}
}

func (e *OTLPHTTPExporter) otlpScope() otlpScope {
	return otlpScope{Name: e.scope.Name, Version: e.scope.Version}
}

// toOTLPAttrs converts attributes to their OTLP KeyValue form.
func toOTLPAttrs(attrs []KeyValue) []otlpKeyValue {
	if len(attrs) == 0 {
		return nil
	}
	out := make([]otlpKeyValue, 0, len(attrs))
	for _, kv := range attrs {
		out = append(out, otlpKeyValue{Key: kv.Key, Value: toAnyValue(kv.Value)})
	}
	return out
}

// toAnyValue maps a Go attribute value to an OTLP AnyValue.
func toAnyValue(v any) otlpAnyValue {
	switch x := v.(type) {
	case string:
		return otlpAnyValue{StringValue: &x}
	case bool:
		return otlpAnyValue{BoolValue: &x}
	case int64:
		s := strconv.FormatInt(x, 10)
		return otlpAnyValue{IntValue: &s}
	case int:
		s := strconv.FormatInt(int64(x), 10)
		return otlpAnyValue{IntValue: &s}
	case float64:
		return otlpAnyValue{DoubleValue: &x}
	default:
		s := fmt.Sprintf("%v", v)
		return otlpAnyValue{StringValue: &s}
	}
}

// nanos formats t as OTLP's Unix-nanoseconds-as-string. A zero time is "0".
func nanos(t time.Time) string {
	if t.IsZero() {
		return "0"
	}
	return strconv.FormatInt(t.UnixNano(), 10)
}

// ParseHeaders parses the OTEL_EXPORTER_OTLP_HEADERS format — a comma-separated
// list of key=value pairs, e.g. "Authorization=Bearer abc,x-tenant=libremail" —
// into a header map. Whitespace around keys and values is trimmed; malformed
// entries (no '=') are skipped.
func ParseHeaders(s string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			continue
		}
		out[k] = strings.TrimSpace(v)
	}
	return out
}

var _ Exporter = (*OTLPHTTPExporter)(nil)
