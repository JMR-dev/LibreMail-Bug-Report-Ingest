//go:build js && wasm

package storage

// WorkerSink is the production ingest.Sink for the Cloudflare Worker. It loads
// the versioned keyring from Cloudflare Secrets Store, resolves the R2 bucket
// binding, and delegates the scrub -> encrypt -> put pipeline to a plain Sink.
//
// Per ADR #5 the keyring secret is fetched inside the request handler (the
// binding's get() is async and the runtime context is only present per-request),
// not at module top-level. The parsed keyring is cached for the isolate lifetime;
// isolates recycle, which is how a rotated `active` version takes over.
//
// Compiled only into the js/wasm Worker; excluded from host builds and tests.

import (
	"context"
	"fmt"
	"sync"
	"syscall/js"

	"github.com/syumai/workers/cloudflare"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/crypto"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/ingest"
)

// WorkerSink implements ingest.Sink against R2 + Secrets Store bindings.
type WorkerSink struct {
	bucketBinding  string
	keyringBinding string

	mu      sync.Mutex
	keyring *crypto.Keyring // cached for the isolate lifetime after first load
}

// NewWorkerSink returns a WorkerSink using the standard binding names. It does no
// I/O and touches no runtime context, so it is safe to construct at main() time;
// bindings are resolved lazily on the first Store call.
func NewWorkerSink() *WorkerSink {
	return &WorkerSink{
		bucketBinding:  BucketBinding,
		keyringBinding: KeyringBinding,
	}
}

// Store loads the keyring (cached), resolves the R2 bucket, and runs the shared
// scrub+encrypt+put pipeline.
func (s *WorkerSink) Store(ctx context.Context, raw []byte) error {
	kr, err := s.loadKeyring()
	if err != nil {
		return fmt.Errorf("storage: load keyring: %w", err)
	}
	store, err := NewR2Store(s.bucketBinding)
	if err != nil {
		return fmt.Errorf("storage: r2 binding: %w", err)
	}
	return NewSink(store, kr).Store(ctx, raw)
}

// loadKeyring returns the cached keyring, loading and parsing it from Secrets
// Store on first use. A failed load is not cached, so it is retried next request.
func (s *WorkerSink) loadKeyring() (*crypto.Keyring, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keyring != nil {
		return s.keyring, nil
	}
	raw, err := getSecret(s.keyringBinding)
	if err != nil {
		return nil, err
	}
	kr, err := crypto.ParseKeyring(raw)
	if err != nil {
		return nil, err
	}
	s.keyring = kr
	return kr, nil
}

// getSecret reads a Cloudflare Secrets Store secret via `await binding.get()`.
// The returned value must never be logged or echoed (ADR #5, Key custody).
func getSecret(binding string) ([]byte, error) {
	b := cloudflare.GetBinding(binding)
	if b.IsUndefined() || b.IsNull() {
		return nil, fmt.Errorf("secrets store binding %q is not bound", binding)
	}
	v, err := await(b.Call("get"))
	if err != nil {
		return nil, err
	}
	if v.IsUndefined() || v.IsNull() {
		return nil, fmt.Errorf("secrets store binding %q returned no value", binding)
	}
	return []byte(v.String()), nil
}

// await resolves a JS Promise from the calling goroutine (the Worker runs each
// handler in its own goroutine, so the JS event loop can settle the promise).
func await(p js.Value) (js.Value, error) {
	resCh := make(chan js.Value, 1)
	errCh := make(chan error, 1)
	var then, catch js.Func
	then = js.FuncOf(func(_ js.Value, args []js.Value) any {
		then.Release()
		catch.Release()
		v := js.Undefined()
		if len(args) > 0 {
			v = args[0]
		}
		resCh <- v
		return js.Undefined()
	})
	catch = js.FuncOf(func(_ js.Value, args []js.Value) any {
		then.Release()
		catch.Release()
		msg := "unknown error"
		if len(args) > 0 {
			msg = args[0].Call("toString").String()
		}
		errCh <- fmt.Errorf("secrets store: %s", msg)
		return js.Undefined()
	})
	p.Call("then", then).Call("catch", catch)
	select {
	case v := <-resCh:
		return v, nil
	case err := <-errCh:
		return js.Value{}, err
	}
}

var _ ingest.Sink = (*WorkerSink)(nil)
