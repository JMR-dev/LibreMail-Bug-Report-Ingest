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
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/telemetry"
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
//
// Observability (#17): when a telemetry provider rides in the request context
// (injected by the Worker), each request emits an "ingest.request" span and a
// correlated structured log classifying the outcome (accepted / rejected /
// error). Instrumentation is observe-only — it wraps the response writer to read
// the status code and never alters the HTTP contract above — and is skipped
// entirely (zero overhead, identical behaviour) when no provider is present,
// which is the default until an OTLP endpoint is configured.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tel := telemetry.FromContext(r.Context())
	if !tel.Enabled() {
		h.serve(w, r)
		return
	}
	ctx, span := tel.StartSpan(r.Context(), "ingest.request",
		telemetry.WithSpanKind(telemetry.SpanKindServer),
		telemetry.WithAttributes(telemetry.String("http.request.method", r.Method)))
	defer span.End()

	sw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	h.serve(sw, r.WithContext(ctx))
	finishIngestSpan(ctx, tel, span, sw.status)
}

// serve is the transport contract from ServeHTTP's doc, unchanged. It is split
// out so ServeHTTP can wrap it with observe-only instrumentation without
// touching a single response path.
func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
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

// statusRecorder wraps an http.ResponseWriter to capture the status code the
// handler wrote, so the ingest span/log can record the outcome. It is a pure
// pass-through: it changes no bytes and no headers.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		// An implicit 200 (no explicit WriteHeader) — not a path this handler
		// takes, but recorded correctly for completeness.
		s.status = http.StatusOK
		s.wrote = true
	}
	return s.ResponseWriter.Write(b)
}

// Ingest outcome vocabulary, recorded as the "ingest.outcome" attribute so a
// backend can group/alert by it.
const (
	outcomeAccepted    = "accepted"
	outcomeRejected    = "rejected"
	outcomeRateLimited = "rate_limited"
	outcomeError       = "error"
)

// alertIngestError is the alert.type for the ingest error signal (issue #17):
// the "elevated ingest error rate" a backend alert keys on. It marks the 5xx
// (e.g. 503 storage-unavailable) responses that indicate a Worker-side fault, as
// opposed to ordinary client rejections (4xx), which are expected and not
// alerted.
const alertIngestError = "ingest.error"

// finishIngestSpan classifies the written status and records the span status,
// attributes, and a correlated log record. Client rejections (4xx) are recorded
// at INFO; server errors (5xx) set the span to Error and emit the alertable
// ingest.error signal.
func finishIngestSpan(ctx context.Context, tel *telemetry.Telemetry, span *telemetry.Span, status int) {
	outcome, reason := classifyIngest(status)
	span.SetAttributes(
		telemetry.Int("http.response.status_code", status),
		telemetry.String("ingest.outcome", outcome),
	)
	if reason != "" {
		span.SetAttributes(telemetry.String("ingest.reason", reason))
	}

	switch outcome {
	case outcomeAccepted:
		span.SetStatus(telemetry.StatusOK, "")
		tel.Info(ctx, "ingest request accepted",
			telemetry.String("ingest.outcome", outcome),
			telemetry.Int("http.response.status_code", status))
	case outcomeError:
		span.SetStatus(telemetry.StatusError, reason)
		attrs := append(telemetry.Alert(alertIngestError),
			telemetry.String("ingest.outcome", outcome),
			telemetry.String("ingest.reason", reason),
			telemetry.Int("http.response.status_code", status))
		tel.Error(ctx, "ingest request failed", attrs...)
	default: // rejected / rate_limited: expected client outcomes, not alerts.
		tel.Info(ctx, "ingest request "+outcome,
			telemetry.String("ingest.outcome", outcome),
			telemetry.String("ingest.reason", reason),
			telemetry.Int("http.response.status_code", status))
	}
}

// classifyIngest maps an HTTP status to the ingest outcome vocabulary. Reasons
// are derived at status granularity (the response paths never echo request
// content, so neither do these).
func classifyIngest(status int) (outcome, reason string) {
	switch {
	case status >= 200 && status < 300:
		return outcomeAccepted, ""
	case status == http.StatusTooManyRequests: // 429 — enforced at the edge today
		return outcomeRateLimited, "rate_limited"
	case status == http.StatusServiceUnavailable: // 503
		return outcomeError, "storage_unavailable"
	case status >= 500:
		return outcomeError, "server_error"
	case status == http.StatusRequestEntityTooLarge: // 413
		return outcomeRejected, "payload_too_large"
	case status == http.StatusUnsupportedMediaType: // 415
		return outcomeRejected, "unsupported_media_type"
	case status == http.StatusMethodNotAllowed: // 405
		return outcomeRejected, "method_not_allowed"
	case status >= 400:
		return outcomeRejected, "invalid_request"
	default:
		return outcomeAccepted, ""
	}
}

// compile-time assurance that the stub sinks satisfy Sink.
var (
	_ Sink = NopSink{}
	_ Sink = (*MemorySink)(nil)
)
