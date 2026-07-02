// Command devserver runs the core bug-report ingest handler on a plain
// net/http server for local development.
//
// It deliberately does not depend on TinyGo or the Cloudflare Workers runtime,
// so `go run ./cmd/devserver` works with the standard Go toolchain and exercises
// the exact same handler that the deployed Wasm Worker serves. It listens on
// :8787 by default (matching wrangler dev's default port); override with ADDR.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/handler"
)

func main() {
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8787"
	}

	log.Printf("devserver listening on %s (try GET / and GET /healthz)", addr)
	if err := http.ListenAndServe(addr, handler.New()); err != nil {
		log.Fatalf("devserver: %v", err)
	}
}
