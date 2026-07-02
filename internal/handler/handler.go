// Package handler holds the core, transport-agnostic HTTP handlers for the
// LibreMail bug-report ingest Worker.
//
// It intentionally carries no build constraints, so it compiles and is
// unit-tested with the standard Go toolchain on the host, and is reused
// verbatim by both the local dev server (cmd/devserver) and the Cloudflare
// Worker Wasm entrypoint (worker). Keeping the request logic here means the same
// http.Handler runs unchanged on the dev server and in the deployed Worker.
package handler

import (
	"encoding/json"
	"net/http"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/ingest"
)

// serviceName identifies this service in responses.
const serviceName = "libremail-bug-report-ingest"

// New returns an http.Handler serving the ingest Worker's endpoints:
//
//	GET  /            -> 200, JSON service/status/message
//	GET  /healthz     -> 200, JSON {"status":"ok"}
//	POST /v1/reports  -> 202 on accept; 400/413/415/405/503 per the ingest contract
//
// Any other path returns 404. On the health/hello endpoints any non-GET method
// returns 405; on /v1/reports any non-POST method returns 405 (Allow: POST).
//
// sink is the storage backend for accepted reports (scrub + encrypt + R2, #9).
// It is injected so the deployed Worker supplies the real R2/Secrets-Store sink
// while cmd/devserver and tests supply an in-memory one. A nil sink defaults to
// ingest.NopSink, which enforces the full HTTP contract but discards bodies.
func New(sink ingest.Sink) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	mux.Handle("/v1/reports", ingest.NewHandler(sink))
	mux.HandleFunc("/", root)
	return mux
}

// root handles the service root. Because "/" is the catch-all pattern in the
// mux, it also rejects unknown paths with 404.
func root(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeJSON(w, http.StatusNotFound, response{Status: "error", Error: "not found"})
		return
	}
	if !isGet(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, response{
		Service: serviceName,
		Status:  "ok",
		Message: "hello from the LibreMail bug-report ingest Worker",
	})
}

// healthz is a liveness/readiness probe endpoint.
func healthz(w http.ResponseWriter, r *http.Request) {
	if !isGet(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, response{Status: "ok"})
}

// isGet reports whether the request method is GET. If not, it writes a 405 with
// an Allow header and returns false.
func isGet(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, response{Status: "error", Error: "method not allowed"})
		return false
	}
	return true
}

// response is the JSON body shape returned by every endpoint. Empty fields are
// omitted so success and error bodies stay minimal.
type response struct {
	Service string `json:"service,omitempty"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// writeJSON writes body as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, body response) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
