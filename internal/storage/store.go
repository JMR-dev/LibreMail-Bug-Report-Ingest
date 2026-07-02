// Package storage persists accepted LibreMail bug-reports as encrypted-at-rest
// objects, implementing the storage half of the ingest pipeline: for each
// accepted report it scrubs PII (internal/scrub, #8), encrypts the scrubbed
// bytes with AES-256-GCM (internal/crypto, ADR #5), and writes only the opaque
// ciphertext frame to the object store. The store never sees plaintext or the
// key.
//
// The package follows the repo's build-tag pattern so it is host-testable
// without TinyGo or the Workers runtime:
//
//   - The ObjectStore interface, MemoryStore, and the Sink (scrub+encrypt+put)
//     carry no build constraints and are unit-tested with `go test`.
//   - The real R2-backed store (R2Store) and the Worker sink that loads the
//     keyring from Cloudflare Secrets Store live behind //go:build js && wasm and
//     are compiled by the Wasm Worker build in CI.
package storage

import (
	"context"
	"errors"
)

// ErrNotFound is returned by ObjectStore.Get when no object exists at the key.
var ErrNotFound = errors.New("storage: object not found")

// Binding names wired in wrangler.jsonc and provisioned by infra (#2).
const (
	// BucketBinding is the R2 bucket binding name (the JS var the Worker reads).
	// The bound bucket is "libremail-bug-reports" (infra defaultR2BucketName).
	BucketBinding = "REPORTS_BUCKET"
	// KeyringBinding is the Cloudflare Secrets Store binding holding the JSON
	// keyring secret, named per ADR #5.
	KeyringBinding = "BUGREPORT_ENC_KEYRING"
)

// ObjectStore is the seam for the opaque object backend. Implementations only
// ever handle already-encrypted frames.
//
//   - Put writes data (a sealed frame) at key, overwriting any existing object.
//   - Get reads the bytes back, or returns ErrNotFound. Get exists mainly for the
//     future publish job (#35) and for tests; the ingest path is write-only.
type ObjectStore interface {
	Put(ctx context.Context, key string, data []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
}
