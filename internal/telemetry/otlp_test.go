package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func sampleSpan() SpanData {
	start := time.Unix(1_700_000_000, 0).UTC()
	return SpanData{
		Name:         "publish.report",
		SpanContext:  SpanContext{TraceID: TraceID{15: 0xab}, SpanID: SpanID{7: 0x01}},
		ParentSpanID: SpanID{7: 0x09},
		Kind:         SpanKindInternal,
		StartTime:    start,
		EndTime:      start.Add(2 * time.Second),
		Attributes: []KeyValue{
			String("report.id", "id-1"),
			Int("publish.deferred", 5),
			Bool("alert", true),
			Float("ratio", 0.5),
		},
		Status: Status{Code: StatusError, Message: "decrypt failed"},
	}
}

// TestBuildTracesPayloadJSON asserts the OTLP/JSON trace shape: hex ids,
// nanosecond string timestamps, int-as-string, and the resource/scope nesting.
func TestBuildTracesPayloadJSON(t *testing.T) {
	exp := NewOTLPHTTPExporter(OTLPConfig{
		Endpoint: "https://otlp.example.com/",
		Resource: []KeyValue{String("service.name", "libremail-bug-report-ingest")},
		Scope:    Scope{Name: "lib", Version: "1.0"},
	})
	b, err := json.Marshal(exp.buildTracesPayload([]SpanData{sampleSpan()}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)

	// Decode back generically and spot-check the load-bearing fields.
	var payload struct {
		ResourceSpans []struct {
			Resource struct {
				Attributes []map[string]any `json:"attributes"`
			} `json:"resource"`
			ScopeSpans []struct {
				Scope struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"scope"`
				Spans []map[string]any `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {
		t.Fatalf("round-trip decode: %v (json=%s)", err, got)
	}
	if len(payload.ResourceSpans) != 1 || len(payload.ResourceSpans[0].ScopeSpans) != 1 {
		t.Fatalf("unexpected nesting: %s", got)
	}
	ss := payload.ResourceSpans[0].ScopeSpans[0]
	if ss.Scope.Name != "lib" || ss.Scope.Version != "1.0" {
		t.Errorf("scope = %+v", ss.Scope)
	}
	if len(ss.Spans) != 1 {
		t.Fatalf("want 1 span, got %d", len(ss.Spans))
	}
	sp := ss.Spans[0]
	// trace_id and span_id are hex strings in OTLP/JSON (a documented exception
	// to proto3's base64 default).
	if sp["traceId"] != "000000000000000000000000000000ab" {
		t.Errorf("traceId = %v, want hex", sp["traceId"])
	}
	if sp["spanId"] != "0000000000000001" {
		t.Errorf("spanId = %v, want hex", sp["spanId"])
	}
	if sp["parentSpanId"] != "0000000000000009" {
		t.Errorf("parentSpanId = %v", sp["parentSpanId"])
	}
	if sp["startTimeUnixNano"] != "1700000000000000000" {
		t.Errorf("startTimeUnixNano = %v", sp["startTimeUnixNano"])
	}
	if sp["endTimeUnixNano"] != "1700000002000000000" {
		t.Errorf("endTimeUnixNano = %v", sp["endTimeUnixNano"])
	}
	// status.code error == 2
	status, _ := sp["status"].(map[string]any)
	if status == nil || status["code"] != float64(2) {
		t.Errorf("status = %v, want code 2", sp["status"])
	}
	// int attribute encoded as string.
	if !strings.Contains(got, `"intValue":"5"`) {
		t.Errorf("expected intValue as string in %s", got)
	}
	if !strings.Contains(got, `"boolValue":true`) {
		t.Errorf("expected boolValue true in %s", got)
	}
	if !strings.Contains(got, `"doubleValue":0.5`) {
		t.Errorf("expected doubleValue 0.5 in %s", got)
	}
}

func TestBuildLogsPayloadJSON(t *testing.T) {
	exp := NewOTLPHTTPExporter(OTLPConfig{Endpoint: "https://otlp.example.com"})
	rec := LogRecord{
		Time:        time.Unix(1_700_000_001, 0).UTC(),
		Severity:    SeverityError,
		Body:        "publish run failed",
		Attributes:  Alert("publish.run_failed"),
		SpanContext: SpanContext{TraceID: TraceID{15: 0x02}, SpanID: SpanID{7: 0x03}},
	}
	b, err := json.Marshal(exp.buildLogsPayload([]LogRecord{rec}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)
	for _, want := range []string{
		`"resourceLogs"`,
		`"severityNumber":17`,
		`"severityText":"ERROR"`,
		`"body":{"stringValue":"publish run failed"}`,
		`"traceId":"00000000000000000000000000000002"`,
		`"spanId":"0000000000000003"`,
		`"alert.type"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("logs JSON missing %q in %s", want, got)
		}
	}
}

// TestOTLPHTTPExporterRoundTrip drives the exporter against a local httptest
// server (NOT a real OTLP backend) to prove it POSTs JSON with the auth header
// to the right signal paths.
func TestOTLPHTTPExporterRoundTrip(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{} // path -> body
	var authHeader, contentType string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen[r.URL.Path] = string(body)
		authHeader = r.Header.Get("Authorization")
		contentType = r.Header.Get("Content-Type")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exp := NewOTLPHTTPExporter(OTLPConfig{
		Endpoint:   srv.URL,
		Headers:    map[string]string{"Authorization": "Bearer secret-token"},
		Resource:   []KeyValue{String("service.name", "svc")},
		HTTPClient: srv.Client(),
	})

	if err := exp.ExportSpans(context.Background(), []SpanData{sampleSpan()}); err != nil {
		t.Fatalf("ExportSpans: %v", err)
	}
	if err := exp.ExportLogs(context.Background(), []LogRecord{{
		Time: time.Now(), Severity: SeverityInfo, Body: "hi",
	}}); err != nil {
		t.Fatalf("ExportLogs: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if _, ok := seen["/v1/traces"]; !ok {
		t.Errorf("no POST to /v1/traces; saw %v", keys(seen))
	}
	if _, ok := seen["/v1/logs"]; !ok {
		t.Errorf("no POST to /v1/logs; saw %v", keys(seen))
	}
	if authHeader != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want the configured secret header", authHeader)
	}
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
	if !strings.Contains(seen["/v1/traces"], `"publish.report"`) {
		t.Errorf("traces body missing span name: %s", seen["/v1/traces"])
	}
}

// TestOTLPExporterNon2xxIsError ensures a non-2xx response surfaces as an error
// (which the provider routes to its error handler, never to the caller).
func TestOTLPExporterNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	exp := NewOTLPHTTPExporter(OTLPConfig{Endpoint: srv.URL, HTTPClient: srv.Client()})
	if err := exp.ExportSpans(context.Background(), []SpanData{sampleSpan()}); err == nil {
		t.Error("expected an error on a 500 response")
	}
}

func TestParseHeaders(t *testing.T) {
	got := ParseHeaders("Authorization=Bearer abc, x-tenant = libremail ,,bad")
	if got["Authorization"] != "Bearer abc" {
		t.Errorf("Authorization = %q", got["Authorization"])
	}
	if got["x-tenant"] != "libremail" {
		t.Errorf("x-tenant = %q", got["x-tenant"])
	}
	if len(got) != 2 {
		t.Errorf("got %d headers, want 2: %v", len(got), got)
	}
	if len(ParseHeaders("")) != 0 {
		t.Error("empty string should yield no headers")
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
