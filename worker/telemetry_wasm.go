//go:build js && wasm

// This file wires OpenTelemetry (#17) into the Cloudflare Worker: it builds the
// OTLP/HTTP exporter from Worker config and injects the telemetry provider into
// the fetch request context so internal/ingest (and, via scheduled_wasm.go,
// internal/schedule + internal/publish) emit spans and structured logs.
//
// The OTLP endpoint/backend is deliberately TBD (issue #17): it is read from a
// plain Worker var and the auth header from a Secrets Store secret, never
// hardcoded. When the endpoint var is unset the provider is nil and all
// instrumentation is a no-op, so the Worker runs exactly as before until an
// endpoint is configured.
//
// Compiled only into the js/wasm Worker; excluded from host builds and tests.
// The non-trivial telemetry logic lives in the build-tag-free, host-tested
// internal/telemetry package; this file is the thin runtime adapter that reads
// the Cloudflare bindings.
package main

import (
	"context"
	"log"
	"net/http"
	"sync"

	"github.com/syumai/workers/cloudflare"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/storage"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/telemetry"
)

// OTEL config names, declared in wrangler.jsonc. The endpoint and service name
// are plain (non-secret) vars; the headers (which carry auth) are a Secrets
// Store secret read via binding.get(), like the encryption keyring.
const (
	// otelEndpointVar is the base OTLP/HTTP URL, e.g. "https://otlp.example.com".
	// TBD (#17): empty/unset => telemetry disabled (no-op).
	otelEndpointVar = "OTEL_EXPORTER_OTLP_ENDPOINT"
	// otelServiceVar overrides the reported service.name.
	otelServiceVar = "OTEL_SERVICE_NAME"
	// otelHeadersSecret is the Secrets Store secret holding the OTLP auth
	// headers in "key=value,key2=value2" form (e.g. "Authorization=Bearer ...").
	otelHeadersSecret = "OTEL_EXPORTER_OTLP_HEADERS"

	otelServiceDefault = "libremail-bug-report-ingest"
	otelScopeName      = "github.com/JMR-dev/LibreMail-Bug-Report-Ingest"
)

var (
	telMu       sync.Mutex
	telProvider *telemetry.Telemetry // cached for the isolate once built
	telBuilt    bool
)

// workerTelemetry lazily builds the telemetry provider from Worker config and
// caches it for the isolate lifetime. It returns nil (a valid no-op provider)
// when OTEL_EXPORTER_OTLP_ENDPOINT is unset — the endpoint is TBD (#17).
//
// It must be called from within a request or scheduled handler: the headers
// secret read is async and per-request on the Workers runtime (mirroring how the
// encryption keyring and admin token are read). The auth header is optional — if
// the secret is unavailable the exporter is still built (some backends accept
// unauthenticated ingest, or auth may live in the endpoint URL); the failure is
// logged, never fatal.
func workerTelemetry() *telemetry.Telemetry {
	telMu.Lock()
	defer telMu.Unlock()
	if telBuilt {
		return telProvider
	}

	endpoint := cloudflare.Getenv(otelEndpointVar)
	if endpoint == "" {
		// Endpoint TBD/unset: leave telemetry disabled. Do not cache, so a later
		// deploy that sets the var (new isolate) picks it up.
		return nil
	}

	headers := map[string]string{}
	if raw, err := storage.ReadSecret(otelHeadersSecret); err != nil {
		log.Printf("telemetry: OTLP headers secret %q unavailable (%v); exporting without auth headers", otelHeadersSecret, err)
	} else {
		headers = telemetry.ParseHeaders(string(raw))
	}

	service := cloudflare.Getenv(otelServiceVar)
	if service == "" {
		service = otelServiceDefault
	}

	exp := telemetry.NewOTLPHTTPExporter(telemetry.OTLPConfig{
		Endpoint: endpoint,
		Headers:  headers,
		Resource: []telemetry.KeyValue{telemetry.String("service.name", service)},
		Scope:    telemetry.Scope{Name: otelScopeName},
	})
	telProvider = telemetry.New(exp, telemetry.WithErrorHandler(func(err error) {
		// Best-effort: a telemetry export failure must never break the request.
		log.Printf("telemetry: export failed: %v", err)
	}))
	telBuilt = true
	return telProvider
}

// withWorkerTelemetry wraps the fetch handler so every request carries the
// telemetry provider in its context (context propagation). When telemetry is
// disabled the provider is nil and the wrapped handler behaves identically.
func withWorkerTelemetry(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := telemetry.NewContext(r.Context(), workerTelemetry())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// scheduledContext returns a context carrying the telemetry provider for the
// weekly publish run, so internal/schedule and internal/publish emit their run
// and per-report spans/logs.
func scheduledContext(ctx context.Context) context.Context {
	return telemetry.NewContext(ctx, workerTelemetry())
}
