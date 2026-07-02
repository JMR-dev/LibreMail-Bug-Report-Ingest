package ingest

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/telemetry"
)

// doWithTelemetry runs one request through h with a telemetry provider injected
// into the request context, returning the recorder and the exporter.
func doWithTelemetry(t *testing.T, h http.Handler, sink Sink, method, contentType, body string) (*httptest.ResponseRecorder, *telemetry.MemoryExporter) {
	t.Helper()
	exp := telemetry.NewMemoryExporter()
	tel := telemetry.New(exp)

	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "/v1/reports", r)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req = req.WithContext(telemetry.NewContext(req.Context(), tel))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, exp
}

// requireSpan returns the single "ingest.request" span, failing if absent.
func requireIngestSpan(t *testing.T, exp *telemetry.MemoryExporter) telemetry.SpanData {
	t.Helper()
	spans := exp.SpansByName("ingest.request")
	if len(spans) != 1 {
		t.Fatalf("got %d ingest.request spans, want 1", len(spans))
	}
	return spans[0]
}

func attrString(t *testing.T, attrs []telemetry.KeyValue, key string) string {
	t.Helper()
	v, ok := telemetry.Attr(attrs, key)
	if !ok {
		t.Fatalf("attribute %q not present in %v", key, attrs)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("attribute %q = %v, not a string", key, v)
	}
	return s
}

func TestIngestAcceptedEmitsSpanAndLog(t *testing.T) {
	rec, exp := doWithTelemetry(t, NewHandler(&MemorySink{}), nil, http.MethodPost, "application/json", validBody)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (contract must be unchanged)", rec.Code)
	}
	span := requireIngestSpan(t, exp)
	if span.Kind != telemetry.SpanKindServer {
		t.Errorf("span kind = %d, want server", span.Kind)
	}
	if span.Status.Code != telemetry.StatusOK {
		t.Errorf("span status = %d, want OK", span.Status.Code)
	}
	if got := attrString(t, span.Attributes, "ingest.outcome"); got != "accepted" {
		t.Errorf("outcome = %q, want accepted", got)
	}
	if v, _ := telemetry.Attr(span.Attributes, "http.response.status_code"); v != int64(202) {
		t.Errorf("status_code attr = %v, want 202", v)
	}

	logs := exp.Logs()
	if len(logs) != 1 {
		t.Fatalf("got %d logs, want 1", len(logs))
	}
	if logs[0].Severity != telemetry.SeverityInfo {
		t.Errorf("log severity = %v, want INFO", logs[0].Severity)
	}
	// The log must correlate to the span.
	if logs[0].SpanContext != span.SpanContext {
		t.Errorf("log not correlated to span: %+v vs %+v", logs[0].SpanContext, span.SpanContext)
	}
}

func TestIngestRejectedEmitsSpanAndLog(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		contentType string
		body        string
		wantStatus  int
		wantReason  string
	}{
		{"wrong content type", http.MethodPost, "text/plain", validBody, http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"malformed json", http.MethodPost, "application/json", `{not json`, http.StatusBadRequest, "invalid_request"},
		{"wrong method", http.MethodGet, "application/json", validBody, http.StatusMethodNotAllowed, "method_not_allowed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, exp := doWithTelemetry(t, NewHandler(&MemorySink{}), nil, tc.method, tc.contentType, tc.body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (contract must be unchanged)", rec.Code, tc.wantStatus)
			}
			span := requireIngestSpan(t, exp)
			if got := attrString(t, span.Attributes, "ingest.outcome"); got != "rejected" {
				t.Errorf("outcome = %q, want rejected", got)
			}
			if got := attrString(t, span.Attributes, "ingest.reason"); got != tc.wantReason {
				t.Errorf("reason = %q, want %q", got, tc.wantReason)
			}
			// A client rejection is NOT a span error and NOT an alert.
			if span.Status.Code == telemetry.StatusError {
				t.Errorf("rejection should not set span status Error")
			}
			logs := exp.Logs()
			if len(logs) != 1 || logs[0].Severity != telemetry.SeverityInfo {
				t.Fatalf("want 1 INFO log for a rejection, got %+v", logs)
			}
			if _, ok := telemetry.Attr(logs[0].Attributes, telemetry.AttrAlert); ok {
				t.Errorf("client rejection must not carry an alert marker")
			}
		})
	}
}

// failSinkErr is a Sink that always fails, to drive the 503 error path.
type failSinkErr struct{}

func (failSinkErr) Store(context.Context, []byte) error { return errors.New("boom") }

// TestIngestErrorEmitsAlertSignal is the "elevated ingest error" signal: a 503
// storage failure sets the span to Error and emits an ERROR log carrying the
// alert marker + alert.type=ingest.error that a backend alert keys on.
func TestIngestErrorEmitsAlertSignal(t *testing.T) {
	rec, exp := doWithTelemetry(t, NewHandler(failSinkErr{}), nil, http.MethodPost, "application/json", validBody)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	span := requireIngestSpan(t, exp)
	if span.Status.Code != telemetry.StatusError {
		t.Errorf("span status = %d, want Error", span.Status.Code)
	}
	if got := attrString(t, span.Attributes, "ingest.outcome"); got != "error" {
		t.Errorf("outcome = %q, want error", got)
	}

	logs := exp.Logs()
	if len(logs) != 1 {
		t.Fatalf("got %d logs, want 1", len(logs))
	}
	l := logs[0]
	if l.Severity != telemetry.SeverityError {
		t.Errorf("severity = %v, want ERROR", l.Severity)
	}
	if v, ok := telemetry.Attr(l.Attributes, telemetry.AttrAlert); !ok || v != true {
		t.Errorf("missing alert marker: %v (present=%v)", v, ok)
	}
	if v, _ := telemetry.Attr(l.Attributes, telemetry.AttrAlertType); v != alertIngestError {
		t.Errorf("alert.type = %v, want %q", v, alertIngestError)
	}
	if l.SpanContext != span.SpanContext {
		t.Errorf("alert log not correlated to span")
	}
}

// TestIngestNoTelemetryIsInert confirms the default path (no provider in ctx)
// emits nothing and preserves the response — the behaviour existing/parallel
// tests rely on.
func TestIngestNoTelemetryIsInert(t *testing.T) {
	h := NewHandler(&MemorySink{})
	// No telemetry in context.
	rec := do(t, h, http.MethodPost, "application/json", validBody)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
}
