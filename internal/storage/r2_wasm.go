//go:build js && wasm

package storage

// R2-backed ObjectStore for the Cloudflare Worker build. It wraps the
// syumai/workers R2 binding API; only sealed (ciphertext) frames are ever
// written, so R2 never holds plaintext or the key (ADR #5).
//
// Compiled only into the js/wasm Worker; excluded from host builds and tests.

import (
	"bytes"
	"context"
	"io"
	"syscall/js"

	"github.com/syumai/workers/cloudflare"
	"github.com/syumai/workers/cloudflare/r2"
)

// R2Store is an ObjectStore backed by a Cloudflare R2 bucket binding.
type R2Store struct {
	bucket *r2.Bucket
	// binding is the raw R2 binding value. The syumai r2.Bucket.List helper takes
	// no options (no prefix, no cursor), so List drives the underlying JS list()
	// directly to page a prefix — see List.
	binding js.Value
}

// NewR2Store resolves the R2 bucket bound as binding (see BucketBinding) from the
// Worker runtime context. It must be called within a request/scheduled handler,
// where the binding is available.
func NewR2Store(binding string) (*R2Store, error) {
	b, err := r2.NewBucket(binding)
	if err != nil {
		return nil, err
	}
	return &R2Store{bucket: b, binding: cloudflare.GetBinding(binding)}, nil
}

// Put writes data at key. The syumai R2 Put reads the whole body into memory and
// PUTs it as bytes.
func (s *R2Store) Put(_ context.Context, key string, data []byte) error {
	_, err := s.bucket.Put(key, io.NopCloser(bytes.NewReader(data)), nil)
	return err
}

// Get reads the object at key, or returns ErrNotFound when it is absent.
func (s *R2Store) Get(_ context.Context, key string) ([]byte, error) {
	obj, err := s.bucket.Get(key)
	if err != nil {
		return nil, err
	}
	if obj == nil || obj.Body == nil {
		return nil, ErrNotFound
	}
	return io.ReadAll(obj.Body)
}

// List returns every key that starts with prefix, in the ascending order R2
// returns them (list is lexicographically ordered). It pages through the whole
// result set via the cursor so a status with more than one list page (R2 caps a
// page at 1000) is still enumerated exactly — important for "list pending" to be
// complete. Only keys are read; object bodies (ciphertext) are never fetched.
func (s *R2Store) List(_ context.Context, prefix string) ([]string, error) {
	var keys []string
	cursor := ""
	for {
		opts := map[string]any{"prefix": prefix, "limit": 1000}
		if cursor != "" {
			opts["cursor"] = cursor
		}
		res, err := await(s.binding.Call("list", js.ValueOf(opts)))
		if err != nil {
			return nil, err
		}
		objs := res.Get("objects")
		for i := 0; i < objs.Length(); i++ {
			keys = append(keys, objs.Index(i).Get("key").String())
		}
		if !res.Get("truncated").Bool() {
			break
		}
		cursor = res.Get("cursor").String()
	}
	return keys, nil
}

// Delete removes the object at key. R2's delete is idempotent (deleting an absent
// key succeeds), which is what makes a retried status transition safe.
func (s *R2Store) Delete(_ context.Context, key string) error {
	return s.bucket.Delete(key)
}

var _ ObjectStore = (*R2Store)(nil)
