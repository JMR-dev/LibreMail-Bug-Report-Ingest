package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// doRequest runs a single request through the handler and returns the recorder.
func doRequest(t *testing.T, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()
	New().ServeHTTP(rec, req)
	return rec
}

// decode parses the JSON response body or fails the test.
func decode(t *testing.T, rec *httptest.ResponseRecorder) response {
	t.Helper()
	var got response
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response body is not valid JSON: %v (body=%q)", err, rec.Body.String())
	}
	return got
}

func TestRoot(t *testing.T) {
	rec := doRequest(t, http.MethodGet, "/")

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("GET / Content-Type = %q, want application/json; charset=utf-8", ct)
	}
	got := decode(t, rec)
	if got.Status != "ok" {
		t.Errorf("GET / status field = %q, want ok", got.Status)
	}
	if got.Service != serviceName {
		t.Errorf("GET / service field = %q, want %q", got.Service, serviceName)
	}
	if got.Message == "" {
		t.Error("GET / message field is empty, want a hello message")
	}
}

func TestHealthz(t *testing.T) {
	rec := doRequest(t, http.MethodGet, "/healthz")

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want %d", rec.Code, http.StatusOK)
	}
	got := decode(t, rec)
	if got.Status != "ok" {
		t.Errorf("GET /healthz status field = %q, want ok", got.Status)
	}
}

func TestUnknownPathReturns404(t *testing.T) {
	rec := doRequest(t, http.MethodGet, "/does-not-exist")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /does-not-exist status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	got := decode(t, rec)
	if got.Status != "error" {
		t.Errorf("404 status field = %q, want error", got.Status)
	}
}

func TestNonGetReturns405(t *testing.T) {
	for _, path := range []string{"/", "/healthz"} {
		rec := doRequest(t, http.MethodPost, path)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s status = %d, want %d", path, rec.Code, http.StatusMethodNotAllowed)
		}
		if allow := rec.Header().Get("Allow"); allow != http.MethodGet {
			t.Errorf("POST %s Allow header = %q, want GET", path, allow)
		}
	}
}
