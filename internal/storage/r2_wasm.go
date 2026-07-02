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

	"github.com/syumai/workers/cloudflare/r2"
)

// R2Store is an ObjectStore backed by a Cloudflare R2 bucket binding.
type R2Store struct {
	bucket *r2.Bucket
}

// NewR2Store resolves the R2 bucket bound as binding (see BucketBinding) from the
// Worker runtime context. It must be called within a request/scheduled handler,
// where the binding is available.
func NewR2Store(binding string) (*R2Store, error) {
	b, err := r2.NewBucket(binding)
	if err != nil {
		return nil, err
	}
	return &R2Store{bucket: b}, nil
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

var _ ObjectStore = (*R2Store)(nil)
