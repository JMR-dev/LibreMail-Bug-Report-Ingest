// Package lifecycle manages the status of stored bug-reports — pending, removed,
// or published (#10) — on top of the storage.ObjectStore seam.
//
// # Status model
//
// Status is encoded in the object key, not inside the (encrypted) object body:
// every report lives at reports/<status>/<id> (see storage.ReportKey). A report
// is born pending at ingest (storage.Sink) and moves to exactly one terminal
// state:
//
//	pending ──MarkRemoved──▶ removed     (a maintainer pulled it, #11)
//	pending ──MarkPublished▶ published   (it became a GitHub issue, #15)
//
// Because status is the key prefix, "list the pending reports" (used by the
// weekly job, #13) is a single prefix listing with no secondary index that could
// drift out of sync, so it returns exactly the pending reports by construction.
//
// # Transitions move ciphertext only
//
// A transition copies the stored object — which is an opaque AES-256-GCM frame
// (internal/crypto) — to the destination status key and deletes the source key.
// The bytes are never decrypted, re-encrypted, or otherwise inspected; no key is
// needed to change status. This keeps the plaintext exposure of the pipeline
// unchanged and lets an unprivileged component (e.g. the maintainer removal tool)
// change status without the decryption key.
//
// # Atomicity, idempotency, retry-safety
//
// Object stores offer no multi-key transaction, so a transition is a copy (Put
// destination) followed by a delete (source), in that order. The ordering is
// chosen to never lose a report: if the process dies after the Put but before the
// Delete, the object is momentarily visible under *both* statuses, but no data is
// lost. Re-running the same transition converges — the Put rewrites identical
// bytes and the Delete removes the leftover source — so a transition is safe to
// retry unconditionally. Deleting an already-absent key is a no-op in every
// ObjectStore, so the retry does not spuriously fail.
//
// A transition whose source is absent is treated as idempotent success when the
// object is already at the destination (an earlier attempt completed), and as an
// ErrUnknownReport otherwise (the id was never pending, or is in a different
// terminal state). Callers therefore may retry MarkRemoved/MarkPublished freely.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/storage"
)

// ErrUnknownReport is returned by a transition when no report with the given id
// exists in the expected source status (and it is not already at the
// destination). It wraps nothing sensitive: the id is an opaque handle.
var ErrUnknownReport = errors.New("lifecycle: unknown pending report id")

// Manager reads and transitions report status over an ObjectStore. It is
// stateless beyond the store reference and safe for concurrent use to the same
// extent the underlying store is.
type Manager struct {
	store storage.ObjectStore
}

// New returns a Manager backed by store. In production store is a *storage.R2Store
// bound to the same bucket the ingest Sink writes to; in tests and cmd/devserver
// it is a *storage.MemoryStore.
func New(store storage.ObjectStore) *Manager {
	return &Manager{store: store}
}

// ListPending returns the ids of all reports currently pending, in ascending
// order (the id's leading UTC timestamp makes this oldest-first, which is the
// order the weekly publish job wants). Given a mix of pending, removed, and
// published reports it returns exactly the pending ones — the removed and
// published reports live under different key prefixes and are not listed.
func (m *Manager) ListPending(ctx context.Context) ([]string, error) {
	prefix := storage.StatusPrefix(storage.StatusPending)
	keys, err := m.store.List(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: list pending: %w", err)
	}
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, strings.TrimPrefix(k, prefix))
	}
	return ids, nil
}

// GetPending returns the stored (still-encrypted) frame for a pending report, or
// storage.ErrNotFound if no such pending report exists. The publish job (#14/#15)
// uses it to fetch a report's ciphertext before decrypting and publishing it;
// this package does not decrypt.
func (m *Manager) GetPending(ctx context.Context, id string) ([]byte, error) {
	return m.store.Get(ctx, storage.ReportKey(storage.StatusPending, id))
}

// MarkRemoved transitions a pending report to removed (#11), excluding it from
// future publish runs. It is idempotent: removing an already-removed report
// succeeds. Removing an id that is not pending (unknown, or already published)
// returns ErrUnknownReport.
func (m *Manager) MarkRemoved(ctx context.Context, id string) error {
	return m.transition(ctx, id, storage.StatusPending, storage.StatusRemoved)
}

// MarkPublished transitions a pending report to published (#15) after it has been
// posted as a GitHub issue, so the next run does not re-publish it. It is
// idempotent: publishing an already-published report succeeds. Publishing an id
// that is not pending (unknown, or already removed) returns ErrUnknownReport.
func (m *Manager) MarkPublished(ctx context.Context, id string) error {
	return m.transition(ctx, id, storage.StatusPending, storage.StatusPublished)
}

// transition moves report id from status to a new status by copying the encrypted
// object to the destination key and deleting the source key. See the package doc
// for the atomicity/idempotency/retry model.
func (m *Manager) transition(ctx context.Context, id string, from, to storage.Status) error {
	fromKey := storage.ReportKey(from, id)
	toKey := storage.ReportKey(to, id)

	data, err := m.store.Get(ctx, fromKey)
	if errors.Is(err, storage.ErrNotFound) {
		// Source absent. Either an earlier attempt already completed the move (the
		// object is at the destination -> idempotent success), or the id was never
		// in the source status (-> unknown).
		if _, derr := m.store.Get(ctx, toKey); derr == nil {
			return nil
		}
		return fmt.Errorf("%w: %q", ErrUnknownReport, id)
	}
	if err != nil {
		return fmt.Errorf("lifecycle: read %s report: %w", from, err)
	}

	// Copy the opaque ciphertext to the destination, then drop the source. Put
	// before Delete so an interruption never loses the report; the operation is
	// idempotent, so a retry converges.
	if err := m.store.Put(ctx, toKey, data); err != nil {
		return fmt.Errorf("lifecycle: write %s report: %w", to, err)
	}
	if err := m.store.Delete(ctx, fromKey); err != nil {
		return fmt.Errorf("lifecycle: delete %s report: %w", from, err)
	}
	return nil
}
