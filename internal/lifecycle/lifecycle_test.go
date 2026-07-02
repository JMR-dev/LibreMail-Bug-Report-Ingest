package lifecycle_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/crypto"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/lifecycle"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/scrub"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/storage"
)

// mustKeyring builds a single-key keyring for sealing realistic ciphertext.
func mustKeyring(t *testing.T) *crypto.Keyring {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kr, err := crypto.NewKeyring(1, map[uint16][]byte{1: key})
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return kr
}

// seal returns an encrypted frame for plaintext (a realistic stored object).
func seal(t *testing.T, kr *crypto.Keyring, plaintext string) []byte {
	t.Helper()
	frame, err := crypto.Seal(kr, []byte(plaintext))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return frame
}

// putStatus writes frame directly at the reports/<status>/<id> key, seeding a
// report in a chosen status without going through a transition.
func putStatus(t *testing.T, store storage.ObjectStore, status storage.Status, id string, frame []byte) {
	t.Helper()
	if err := store.Put(context.Background(), storage.ReportKey(status, id), frame); err != nil {
		t.Fatalf("seed %s/%s: %v", status, id, err)
	}
}

// TestListPendingExactness is the ticket's acceptance criterion: given a mix of
// reports in different states, ListPending returns exactly the pending ids.
func TestListPendingExactness(t *testing.T) {
	ctx := context.Background()
	kr := mustKeyring(t)
	store := storage.NewMemoryStore()
	m := lifecycle.New(store)

	// A deliberately interleaved mix across all three states.
	putStatus(t, store, storage.StatusPending, "id-a", seal(t, kr, "a"))
	putStatus(t, store, storage.StatusRemoved, "id-b", seal(t, kr, "b"))
	putStatus(t, store, storage.StatusPending, "id-c", seal(t, kr, "c"))
	putStatus(t, store, storage.StatusPublished, "id-d", seal(t, kr, "d"))
	putStatus(t, store, storage.StatusPending, "id-e", seal(t, kr, "e"))
	putStatus(t, store, storage.StatusRemoved, "id-f", seal(t, kr, "f"))

	got, err := m.ListPending(ctx)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	want := []string{"id-a", "id-c", "id-e"} // sorted; only the pending ones
	if !slices.Equal(got, want) {
		t.Errorf("ListPending = %v, want exactly %v", got, want)
	}
}

// TestNewReportsAreListedAsPending proves the #9 ingest Sink now lands reports in
// the pending state, discoverable via ListPending, and readable back as the same
// ciphertext (which still decrypts to the scrubbed body).
func TestNewReportsAreListedAsPending(t *testing.T) {
	ctx := context.Background()
	kr := mustKeyring(t)
	store := storage.NewMemoryStore()
	sink := storage.NewSink(store, kr) // default key func -> reports/pending/<id>
	m := lifecycle.New(store)

	raw := `{"appVersion":"1.0.0","platform":"android","report":"boom from 203.0.113.7"}`
	if err := sink.Store(ctx, []byte(raw)); err != nil {
		t.Fatalf("sink.Store: %v", err)
	}

	ids, err := m.ListPending(ctx)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("ListPending returned %d ids, want 1 (the just-ingested report)", len(ids))
	}

	frame, err := m.GetPending(ctx, ids[0])
	if err != nil {
		t.Fatalf("GetPending(%q): %v", ids[0], err)
	}
	opened, err := crypto.Open(kr, frame)
	if err != nil {
		t.Fatalf("Open pending frame: %v", err)
	}
	if !bytes.Equal(opened, scrub.Scrub([]byte(raw))) {
		t.Error("pending frame did not decrypt to the scrubbed body")
	}
}

// TestMarkRemoved checks pending -> removed: the report leaves the pending set,
// appears under removed, and its bytes are the unchanged ciphertext.
func TestMarkRemoved(t *testing.T) {
	transitionCase(t, "removed",
		func(m *lifecycle.Manager, id string) error { return m.MarkRemoved(context.Background(), id) },
		storage.StatusRemoved)
}

// TestMarkPublished checks pending -> published with the same guarantees.
func TestMarkPublished(t *testing.T) {
	transitionCase(t, "published",
		func(m *lifecycle.Manager, id string) error { return m.MarkPublished(context.Background(), id) },
		storage.StatusPublished)
}

// transitionCase is the shared body for the two happy-path transitions.
func transitionCase(t *testing.T, name string, do func(*lifecycle.Manager, string) error, target storage.Status) {
	t.Helper()
	ctx := context.Background()
	kr := mustKeyring(t)
	store := storage.NewMemoryStore()
	m := lifecycle.New(store)

	const id = "id-x"
	frame := seal(t, kr, "sensitive report body")
	putStatus(t, store, storage.StatusPending, id, frame)
	// A second pending report that must be unaffected by the transition.
	putStatus(t, store, storage.StatusPending, "id-keep", seal(t, kr, "other"))

	if err := do(m, id); err != nil {
		t.Fatalf("%s transition: %v", name, err)
	}

	// It left the pending set (only the untouched report remains).
	pending, _ := m.ListPending(ctx)
	if !slices.Equal(pending, []string{"id-keep"}) {
		t.Errorf("after %s, ListPending = %v, want [id-keep]", name, pending)
	}

	// The source key is gone.
	if _, err := store.Get(ctx, storage.ReportKey(storage.StatusPending, id)); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("pending key still present after %s (err=%v)", name, err)
	}

	// It appears under the target status with byte-identical ciphertext...
	moved, err := store.Get(ctx, storage.ReportKey(target, id))
	if err != nil {
		t.Fatalf("get %s object: %v", target, err)
	}
	if !bytes.Equal(moved, frame) {
		t.Errorf("%s object bytes changed by the transition; must move ciphertext verbatim", target)
	}
	// ...and the frame is intact: it still decrypts to the original plaintext,
	// proving the transition neither decrypted nor corrupted it.
	opened, err := crypto.Open(kr, moved)
	if err != nil {
		t.Fatalf("Open moved frame: %v", err)
	}
	if string(opened) != "sensitive report body" {
		t.Errorf("moved frame decrypted to %q, want original plaintext", opened)
	}
}

// TestTransitionIdempotentRetry proves a transition can be retried safely: calling
// it twice ends in the same single-object state and the second call returns nil.
func TestTransitionIdempotentRetry(t *testing.T) {
	ctx := context.Background()
	kr := mustKeyring(t)
	store := storage.NewMemoryStore()
	m := lifecycle.New(store)

	const id = "id-1"
	putStatus(t, store, storage.StatusPending, id, seal(t, kr, "body"))

	if err := m.MarkPublished(ctx, id); err != nil {
		t.Fatalf("first MarkPublished: %v", err)
	}
	if err := m.MarkPublished(ctx, id); err != nil {
		t.Errorf("second MarkPublished (retry) = %v, want nil (idempotent)", err)
	}

	if pending, _ := m.ListPending(ctx); len(pending) != 0 {
		t.Errorf("ListPending = %v after publish, want empty", pending)
	}
	if published, _ := store.List(ctx, storage.StatusPrefix(storage.StatusPublished)); len(published) != 1 {
		t.Errorf("published objects = %d, want exactly 1 (no duplicate from retry)", len(published))
	}
}

// TestTransitionConvergesFromInterruptedState simulates a crash after the copy
// (Put destination) but before the delete (source): the object exists under both
// statuses. Re-running the transition must converge to only the destination.
func TestTransitionConvergesFromInterruptedState(t *testing.T) {
	ctx := context.Background()
	kr := mustKeyring(t)
	store := storage.NewMemoryStore()
	m := lifecycle.New(store)

	const id = "id-2"
	frame := seal(t, kr, "body")
	putStatus(t, store, storage.StatusPending, id, frame)   // source (leftover)
	putStatus(t, store, storage.StatusPublished, id, frame) // destination (already copied)

	// Mid-transition the report is visible in both sets.
	if pending, _ := m.ListPending(ctx); !slices.Contains(pending, id) {
		t.Fatalf("precondition: expected %q to appear pending mid-transition", id)
	}

	if err := m.MarkPublished(ctx, id); err != nil {
		t.Fatalf("MarkPublished (convergence): %v", err)
	}

	if pending, _ := m.ListPending(ctx); slices.Contains(pending, id) {
		t.Errorf("after convergence, %q still pending", id)
	}
	if _, err := store.Get(ctx, storage.ReportKey(storage.StatusPublished, id)); err != nil {
		t.Errorf("published object missing after convergence: %v", err)
	}
}

// TestUnknownIdErrors covers transitions of ids that are not pending.
func TestUnknownIdErrors(t *testing.T) {
	ctx := context.Background()
	kr := mustKeyring(t)
	store := storage.NewMemoryStore()
	m := lifecycle.New(store)

	// Never-seen id.
	if err := m.MarkRemoved(ctx, "ghost"); !errors.Is(err, lifecycle.ErrUnknownReport) {
		t.Errorf("MarkRemoved(unknown) err = %v, want ErrUnknownReport", err)
	}
	if err := m.MarkPublished(ctx, "ghost"); !errors.Is(err, lifecycle.ErrUnknownReport) {
		t.Errorf("MarkPublished(unknown) err = %v, want ErrUnknownReport", err)
	}

	// An id in a terminal state cannot be transitioned again from pending: a
	// removed report is not publishable, and a published report is not removable.
	putStatus(t, store, storage.StatusRemoved, "was-removed", seal(t, kr, "x"))
	if err := m.MarkPublished(ctx, "was-removed"); !errors.Is(err, lifecycle.ErrUnknownReport) {
		t.Errorf("MarkPublished(removed id) err = %v, want ErrUnknownReport", err)
	}
	putStatus(t, store, storage.StatusPublished, "was-published", seal(t, kr, "y"))
	if err := m.MarkRemoved(ctx, "was-published"); !errors.Is(err, lifecycle.ErrUnknownReport) {
		t.Errorf("MarkRemoved(published id) err = %v, want ErrUnknownReport", err)
	}
}

// TestGetPending covers the report-fetch helper the publish job relies on.
func TestGetPending(t *testing.T) {
	ctx := context.Background()
	kr := mustKeyring(t)
	store := storage.NewMemoryStore()
	m := lifecycle.New(store)

	frame := seal(t, kr, "body")
	putStatus(t, store, storage.StatusPending, "id-1", frame)

	got, err := m.GetPending(ctx, "id-1")
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if !bytes.Equal(got, frame) {
		t.Error("GetPending returned different bytes than were stored")
	}

	if _, err := m.GetPending(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("GetPending(missing) err = %v, want ErrNotFound", err)
	}
}
