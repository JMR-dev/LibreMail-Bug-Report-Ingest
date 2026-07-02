// Command devserver runs the core bug-report ingest handler on a plain
// net/http server for local development.
//
// It deliberately does not depend on TinyGo or the Cloudflare Workers runtime,
// so `go run ./cmd/devserver` works with the standard Go toolchain and exercises
// the exact same handler that the deployed Wasm Worker serves. It listens on
// :8787 by default (matching wrangler dev's default port); override with ADDR.
//
// The ingest path is wired with the real scrub+encrypt storage Sink (#9) backed
// by an in-memory object store and a throwaway per-run AES-256 key, so a POST
// /v1/reports exercises the full pipeline locally. Stored objects live only for
// the process lifetime.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/crypto"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/handler"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/storage"
)

func main() {
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8787"
	}

	// A throwaway keyring: a single random key generated at startup. Reports are
	// scrubbed, encrypted under it, and held in memory; nothing is persisted.
	key, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("devserver: generate key: %v", err)
	}
	keyring, err := crypto.NewKeyring(1, map[uint16][]byte{1: key})
	if err != nil {
		log.Fatalf("devserver: build keyring: %v", err)
	}
	sink := storage.NewSink(storage.NewMemoryStore(), keyring)

	log.Printf("devserver listening on %s (try GET / and GET /healthz)", addr)
	if err := http.ListenAndServe(addr, handler.New(sink)); err != nil {
		log.Fatalf("devserver: %v", err)
	}
}
