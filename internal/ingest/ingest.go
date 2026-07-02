// Package ingest implements the LibreMail bug-report ingest endpoint,
// POST /v1/reports.
//
// It owns the Worker-side half of the abuse policy fixed in ADR #6
// (docs/decisions/labels-and-abuse.md): the 256 KiB payload cap and JSON schema
// validation, plus the 202/400/413/415/405 response contract. Rate limiting
// (429) and volumetric shedding are NOT implemented here: per ADR #6 those are
// enforced at the Cloudflare edge via Pulumi-provisioned Rate Limiting rules
// (ticket #2), before the Worker ever runs. The endpoint does answer 503 when
// its storage Sink fails, matching the "storage unavailable" row of the ADR.
//
// The package is plain, build-tag-free Go so it is host-testable with the
// standard toolchain (go test ./...) and reused verbatim by the Wasm Worker.
package ingest

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
)

// MaxBodyBytes is the hard cap on the request body: 256 KiB (262,144 bytes),
// per ADR #6 §2.1. Bodies larger than this are rejected with 413.
const MaxBodyBytes = 256 * 1024

// contentTypeJSON is the only accepted request media type (parameters such as
// "; charset=utf-8" are allowed and ignored).
const contentTypeJSON = "application/json"

// Handler serves POST /v1/reports. Construct it with NewHandler.
type Handler struct {
	sink Sink
}

// NewHandler returns a Handler that stores accepted reports in sink. A nil sink
// is replaced with NopSink, so the endpoint is always safe to construct.
func NewHandler(sink Sink) *Handler {
	if sink == nil {
		sink = NopSink{}
	}
	return &Handler{sink: sink}
}

// ServeHTTP implements the ingest response contract from ADR #6 §2.4:
//
//	POST + valid JSON within the size cap -> 202 {"status":"accepted"}
//	non-POST method                       -> 405 (Allow: POST)
//	Content-Type not application/json      -> 415
//	body over 256 KiB                      -> 413 (Content-Length fast path + hard read cap)
//	malformed JSON / failed validation     -> 400
//	sink failure                           -> 503
//
// Error bodies are generic ({"error":"..."}) and never reflect request content.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusUnsupportedMediaType, "content-type must be application/json")
		return
	}

	// Fast path: reject an honestly-declared oversized body before reading it.
	if r.ContentLength > MaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "payload too large")
		return
	}

	// Hard cap: enforce the limit on the stream too, so a missing, chunked, or
	// lying Content-Length cannot smuggle a larger body past the fast path.
	// MaxBytesReader allows up to MaxBodyBytes and errors on the next byte.
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload too large")
			return
		}
		writeError(w, http.StatusBadRequest, "could not read request body")
		return
	}

	if _, err := parseReport(raw); err != nil {
		writeError(w, http.StatusBadRequest, "invalid report")
		return
	}

	// Store the raw, validated body. Scrubbing/encryption happen downstream
	// (#8/#9) behind the Sink; this package stays contract-only.
	if err := h.sink.Store(r.Context(), raw); err != nil {
		writeError(w, http.StatusServiceUnavailable, "storage unavailable")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

// isJSONContentType reports whether ct declares an application/json body,
// tolerating media-type parameters (e.g. "application/json; charset=utf-8") and
// case. A missing or unparseable Content-Type is rejected.
func isJSONContentType(ct string) bool {
	if strings.TrimSpace(ct) == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mediaType == contentTypeJSON
}

// writeJSON writes body as a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeError writes a generic {"error": reason} body. reason is a fixed,
// caller-supplied string and must never include request-derived content.
func writeError(w http.ResponseWriter, status int, reason string) {
	writeJSON(w, status, map[string]string{"error": reason})
}

// compile-time assurance that the stub sinks satisfy Sink.
var (
	_ Sink = NopSink{}
	_ Sink = (*MemorySink)(nil)
)
