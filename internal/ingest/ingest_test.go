package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// validBody is a minimal well-formed v1 report.
const validBody = `{"appVersion":"1.4.2 (142)","platform":"android","osVersion":"Android 14","device":"Pixel 7","clientTimestamp":"2026-07-02T12:34:56Z","report":"NPE in SyncService\n<logs>"}`

// newHandler returns a Handler backed by a MemorySink for assertions.
func newHandler(t *testing.T) (*Handler, *MemorySink) {
	t.Helper()
	sink := &MemorySink{}
	return NewHandler(sink), sink
}

// do runs one request through h and returns the recorder.
func do(t *testing.T, h http.Handler, method, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "/v1/reports", r)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// decodeMap parses the JSON response body into a map.
func decodeMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response body is not valid JSON: %v (body=%q)", err, rec.Body.String())
	}
	return got
}

func TestAccepted202(t *testing.T) {
	h, sink := newHandler(t)
	rec := do(t, h, http.MethodPost, "application/json", validBody)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d (body=%q)", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json; charset=utf-8", ct)
	}
	if got := decodeMap(t, rec); got["status"] != "accepted" {
		t.Errorf("status field = %q, want accepted", got["status"])
	}
	if sink.Len() != 1 {
		t.Fatalf("sink stored %d reports, want 1", sink.Len())
	}
	if stored := sink.Reports()[0]; !bytes.Equal(stored, []byte(validBody)) {
		t.Errorf("sink stored %q, want the raw body %q", stored, validBody)
	}
}

func TestAcceptedContentTypeWithCharset(t *testing.T) {
	h, _ := newHandler(t)
	for _, ct := range []string{"application/json", "application/json; charset=utf-8", "application/JSON", "  application/json  "} {
		rec := do(t, h, http.MethodPost, ct, validBody)
		if rec.Code != http.StatusAccepted {
			t.Errorf("Content-Type %q: status = %d, want %d", ct, rec.Code, http.StatusAccepted)
		}
	}
}

func TestAcceptedAtExactLimit(t *testing.T) {
	h, _ := newHandler(t)
	prefix := `{"appVersion":"1.0.0","platform":"android","report":"`
	suffix := `"}`
	pad := MaxBodyBytes - len(prefix) - len(suffix)
	body := prefix + strings.Repeat("x", pad) + suffix
	if len(body) != MaxBodyBytes {
		t.Fatalf("test setup: body len = %d, want exactly %d", len(body), MaxBodyBytes)
	}
	rec := do(t, h, http.MethodPost, "application/json", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("body of exactly %d bytes: status = %d, want %d", MaxBodyBytes, rec.Code, http.StatusAccepted)
	}
}

func TestOversizedViaContentLength413(t *testing.T) {
	h, sink := newHandler(t)
	big := strings.Repeat("x", MaxBodyBytes+1024)
	body := `{"appVersion":"1.0.0","platform":"android","report":"` + big + `"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/reports", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if req.ContentLength <= MaxBodyBytes {
		t.Fatalf("test setup: ContentLength = %d, want > %d (fast path must trigger)", req.ContentLength, MaxBodyBytes)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
	if sink.Len() != 0 {
		t.Errorf("sink stored %d reports, want 0 (oversized must not be stored)", sink.Len())
	}
}

func TestOversizedViaStreamedBody413(t *testing.T) {
	h, sink := newHandler(t)
	big := strings.Repeat("x", MaxBodyBytes+1024)
	body := `{"appVersion":"1.0.0","platform":"android","report":"` + big + `"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/reports", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Simulate a missing/lying Content-Length so the fast path is bypassed and
	// only the streamed MaxBytesReader cap can catch the oversized body.
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
	if sink.Len() != 0 {
		t.Errorf("sink stored %d reports, want 0 (oversized must not be stored)", sink.Len())
	}
}

func TestWrongContentType415(t *testing.T) {
	h, _ := newHandler(t)
	for _, ct := range []string{"text/plain", "application/xml", "multipart/form-data", ""} {
		rec := do(t, h, http.MethodPost, ct, validBody)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("Content-Type %q: status = %d, want %d", ct, rec.Code, http.StatusUnsupportedMediaType)
		}
	}
}

func TestMalformedJSON400(t *testing.T) {
	h, _ := newHandler(t)
	cases := map[string]string{
		"truncated object": `{"appVersion":"1.0.0","platform":`,
		"not json":         `this is not json`,
		"empty body":       ``,
		"trailing garbage": `{"appVersion":"1.0.0","platform":"android","report":"x"} garbage`,
		"json array":       `["not","an","object"]`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rec := do(t, h, http.MethodPost, "application/json", body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d (body=%q)", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		})
	}
}

func TestSchemaValidation400(t *testing.T) {
	h, _ := newHandler(t)
	cases := map[string]string{
		"missing appVersion":  `{"platform":"android","report":"boom"}`,
		"empty appVersion":    `{"appVersion":"  ","platform":"android","report":"boom"}`,
		"missing platform":    `{"appVersion":"1.0.0","report":"boom"}`,
		"missing report":      `{"appVersion":"1.0.0","platform":"android"}`,
		"empty report":        `{"appVersion":"1.0.0","platform":"android","report":"   "}`,
		"bad clientTimestamp": `{"appVersion":"1.0.0","platform":"android","report":"boom","clientTimestamp":"not-a-time"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rec := do(t, h, http.MethodPost, "application/json", body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d (body=%q)", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		})
	}
}

func TestWrongMethod405(t *testing.T) {
	h, _ := newHandler(t)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead} {
		rec := do(t, h, method, "application/json", validBody)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want %d", method, rec.Code, http.StatusMethodNotAllowed)
		}
		if allow := rec.Header().Get("Allow"); allow != http.MethodPost {
			t.Errorf("%s: Allow header = %q, want POST", method, allow)
		}
	}
}

// failSink always fails, to exercise the 503 storage-unavailable path.
type failSink struct{}

func (failSink) Store(context.Context, []byte) error { return errors.New("boom") }

func TestStorageFailure503(t *testing.T) {
	h := NewHandler(failSink{})
	rec := do(t, h, http.MethodPost, "application/json", validBody)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestErrorBodiesDoNotEchoRequest(t *testing.T) {
	h, _ := newHandler(t)
	secret := "SUPER-SECRET-TOKEN-DO-NOT-LEAK"
	body := `{"appVersion":"1.0.0","platform":"android","report":"boom","clientTimestamp":"` + secret + `"}`
	rec := do(t, h, http.MethodPost, "application/json", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Errorf("error body echoed request content: %q", rec.Body.String())
	}
}

func TestNilSinkDefaultsToNop(t *testing.T) {
	h := NewHandler(nil)
	rec := do(t, h, http.MethodPost, "application/json", validBody)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d (nil sink should default to NopSink)", rec.Code, http.StatusAccepted)
	}
}
