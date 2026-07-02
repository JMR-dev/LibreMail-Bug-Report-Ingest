//go:build js && wasm

package main

// workerAdminBackend is the production handler.AdminBackend for the maintainer
// admin API (#11) in the Cloudflare Worker.
//
// The admin secret and the R2 bucket binding are only available inside a request
// on the Workers runtime (the Secrets Store get() is async and per-request; the
// R2 binding resolves from the request context), so — unlike the dev server,
// which injects a ready Manager + token at startup — this backend resolves both
// lazily on each call. The token is read from Secrets Store (AdminTokenBinding)
// and the lifecycle Manager is built over a fresh R2-backed store per operation.
// This mirrors how WorkerSink loads its keyring lazily.
//
// Compiled only into the js/wasm Worker; excluded from host builds and tests.

import (
	"context"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/lifecycle"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/storage"
)

type workerAdminBackend struct{}

// AdminToken reads the shared admin secret from Cloudflare Secrets Store. A load
// failure (unbound/empty binding) returns an error, which the handler surfaces as
// 503; the handler independently fails closed (401) on an empty secret value.
func (workerAdminBackend) AdminToken(context.Context) (string, error) {
	tok, err := storage.ReadSecret(storage.AdminTokenBinding)
	if err != nil {
		return "", err
	}
	return string(tok), nil
}

// ListPending builds an R2-backed lifecycle Manager for this request and returns
// the pending report ids.
func (workerAdminBackend) ListPending(ctx context.Context) ([]string, error) {
	mgr, err := managerForRequest()
	if err != nil {
		return nil, err
	}
	return mgr.ListPending(ctx)
}

// MarkRemoved builds an R2-backed lifecycle Manager for this request and
// transitions the report pending -> removed.
func (workerAdminBackend) MarkRemoved(ctx context.Context, id string) error {
	mgr, err := managerForRequest()
	if err != nil {
		return err
	}
	return mgr.MarkRemoved(ctx, id)
}

// managerForRequest resolves the R2 bucket binding (available within a request)
// and wraps it in a lifecycle Manager.
func managerForRequest() (*lifecycle.Manager, error) {
	store, err := storage.NewR2Store(storage.BucketBinding)
	if err != nil {
		return nil, err
	}
	return lifecycle.New(store), nil
}
