//go:build js && wasm

// Command worker is the Cloudflare Workers (Wasm) entrypoint.
//
// It is compiled only for the js/wasm target by TinyGo (see the "Build & run
// locally" section of the README). The build constraint above keeps this file
// out of host builds and `go test ./...`, so the standard Go toolchain never
// needs the Workers runtime. It wires the shared core handler into the
// syumai/workers adapter, which bridges Go's net/http model to the Workers
// fetch event.
package main

import (
	"github.com/syumai/workers"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/handler"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/storage"
)

func main() {
	// The real storage Sink (#9): scrub -> AES-256-GCM encrypt -> R2 put, with the
	// keyring loaded from Cloudflare Secrets Store on first request. Bindings
	// (REPORTS_BUCKET, BUGREPORT_ENC_KEYRING) are declared in wrangler.jsonc.
	workers.Serve(handler.New(storage.NewWorkerSink()))
}
