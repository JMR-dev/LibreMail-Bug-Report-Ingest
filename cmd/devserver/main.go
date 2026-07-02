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
//
// The maintainer admin API (#11) is wired over a lifecycle.Manager sharing that
// same in-memory store, so reports ingested via POST /v1/reports are immediately
// listable and removable under /v1/admin/reports. Its shared-secret bearer token
// comes from the ADMIN_TOKEN env var; if unset, the admin routes fail closed
// (every request 401s), matching production's fail-closed behaviour. Set
// ADMIN_TOKEN=... to exercise the admin API (the Bruno api-tests do this).
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/crypto"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/handler"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/lifecycle"
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

	// One shared in-memory store backs both the ingest Sink and the admin
	// lifecycle Manager, so an ingested report is visible to the admin API.
	store := storage.NewMemoryStore()
	sink := storage.NewSink(store, keyring)
	adminToken := os.Getenv("ADMIN_TOKEN")
	admin := handler.NewManagerBackend(lifecycle.New(store), adminToken)

	if adminToken == "" {
		log.Print("devserver: ADMIN_TOKEN is unset; /v1/admin routes fail closed (401). Set ADMIN_TOKEN to enable them.")
	} else {
		log.Print("devserver: admin API enabled at /v1/admin/reports (bearer token from ADMIN_TOKEN)")
	}
	log.Printf("devserver listening on %s (try GET / and GET /healthz)", addr)
	if err := http.ListenAndServe(addr, handler.New(sink, admin)); err != nil {
		log.Fatalf("devserver: %v", err)
	}
}
