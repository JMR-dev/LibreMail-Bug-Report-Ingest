package publish

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/crypto"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/lifecycle"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/storage"
)

// The lifecycle Manager must satisfy the write-half seam #15 wires onPublished to.
var _ Marker = (*lifecycle.Manager)(nil)

// putPending seeds one pending report (a sealed frame) at reports/pending/<id>,
// exactly as the ingest Sink would, so ListPending discovers it. The frame
// decrypts to sampleReport(id), whose free text embeds the id so a mock creator
// can be scripted to fail a specific report by inspecting the issue body.
func putPending(t *testing.T, store *storage.MemoryStore, kr *crypto.Keyring, id string) {
	t.Helper()
	frame := seal(t, kr, reportJSON(t, sampleReport(id)))
	if err := store.Put(context.Background(), storage.ReportKey(storage.StatusPending, id), frame); err != nil {
		t.Fatalf("seed pending %s: %v", id, err)
	}
}

func publishedCount(t *testing.T, store *storage.MemoryStore) int {
	t.Helper()
	keys, err := store.List(context.Background(), storage.StatusPrefix(storage.StatusPublished))
	if err != nil {
		t.Fatalf("list published: %v", err)
	}
	return len(keys)
}

// TestMarkPublishedTransitionsAndDedupsAcrossRuns is the ticket's core acceptance:
// with WithMarkPublished wired to a real lifecycle.Manager, a full run where every
// report publishes leaves all of them `published` (ListPending empty), and a
// second run over the (now empty) pending set creates NO new issues.
func TestMarkPublishedTransitionsAndDedupsAcrossRuns(t *testing.T) {
	ctx := context.Background()
	kr := mustKeyring(t)
	store := storage.NewMemoryStore()
	ids := []string{"20260101T000000-aaaa", "20260102T000000-bbbb", "20260103T000000-cccc"}
	for _, id := range ids {
		putPending(t, store, kr, id)
	}
	manager := lifecycle.New(store)
	mc := &mockCreator{}
	// The same Manager is both the pending getter and the mark-published marker,
	// mirroring the Worker's buildPublish wiring.
	pub := newPublisher(mc, kr, manager, WithMarkPublished(manager))

	// --- Run 1: list pending, publish; every report succeeds. ---
	run1, err := manager.ListPending(ctx)
	if err != nil {
		t.Fatalf("run1 ListPending: %v", err)
	}
	if !slices.Equal(run1, ids) {
		t.Fatalf("run1 pending = %v, want %v", run1, ids)
	}
	if err := pub.Publish(ctx, run1); err != nil {
		t.Fatalf("run1 Publish: %v", err)
	}
	if len(mc.created) != len(ids) {
		t.Fatalf("run1 created %d issues, want %d", len(mc.created), len(ids))
	}

	// Acceptance: after the run every report shows `published` and none is pending.
	if pending, _ := manager.ListPending(ctx); len(pending) != 0 {
		t.Errorf("after run1 ListPending = %v, want empty (all marked published)", pending)
	}
	if got := publishedCount(t, store); got != len(ids) {
		t.Errorf("published objects = %d, want %d", got, len(ids))
	}

	// --- Run 2: list pending (now empty) and publish again -> no duplication. ---
	run2, _ := manager.ListPending(ctx)
	if len(run2) != 0 {
		t.Fatalf("run2 pending = %v, want empty", run2)
	}
	if err := pub.Publish(ctx, run2); err != nil {
		t.Fatalf("run2 Publish: %v", err)
	}
	if len(mc.created) != len(ids) {
		t.Errorf("run2 created new issues (total now %d), want no duplication (still %d)", len(mc.created), len(ids))
	}
}

// TestMarkPublishedPartialFailureRetriesOnlyFailedNextRun is the ticket's
// partial-failure acceptance: report N's create fails while the others succeed, so
// 1..N-1 are `published` and N stays `pending`; the next run retries only N
// (creating exactly one issue for it) and does not duplicate 1..N-1.
func TestMarkPublishedPartialFailureRetriesOnlyFailedNextRun(t *testing.T) {
	ctx := context.Background()
	kr := mustKeyring(t)
	store := storage.NewMemoryStore()
	// Oldest-first order after ListPending sorts ascending: aaaa, bbbb, cccc.
	ids := []string{"20260101T000000-aaaa", "20260102T000000-bbbb", "20260103T000000-cccc"}
	for _, id := range ids {
		putPending(t, store, kr, id)
	}
	failID := ids[len(ids)-1] // report N (the last/oldest-first-processed report)
	manager := lifecycle.New(store)

	// Create fails the FIRST time it sees report N (identified by its id in the body,
	// which sampleReport embeds), and succeeds otherwise. Numbers are cosmetic.
	num := 0
	failSeen := 0
	mc := &mockCreator{createFn: func(_, body string, _ []string) (CreatedIssue, error) {
		if strings.Contains(body, failID) && failSeen == 0 {
			failSeen++
			return CreatedIssue{}, errors.New("github: create issue: gave up after 5 attempt(s)")
		}
		num++
		return CreatedIssue{Number: num, HTMLURL: fmt.Sprintf("https://github.com/o/r/issues/%d", num)}, nil
	}}
	pub := newPublisher(mc, kr, manager, WithMarkPublished(manager))

	// --- Run 1: N fails, the rest publish. ---
	run1, _ := manager.ListPending(ctx)
	err := pub.Publish(ctx, run1)
	if err == nil {
		t.Fatal("run1 Publish: expected a surfaced error for the failed report")
	}
	if !strings.Contains(err.Error(), failID) {
		t.Errorf("run1 error should name the failed report %s: %v", failID, err)
	}
	// N-1 issues created; N was not.
	if len(mc.created) != len(ids)-1 {
		t.Errorf("run1 created %d issues, want %d (report N isolated)", len(mc.created), len(ids)-1)
	}
	// N-1 are published; N remains the only pending report.
	if got := publishedCount(t, store); got != len(ids)-1 {
		t.Errorf("after run1 published objects = %d, want %d", got, len(ids)-1)
	}
	if pending, _ := manager.ListPending(ctx); !slices.Equal(pending, []string{failID}) {
		t.Errorf("after run1 ListPending = %v, want exactly [%s] (only the failed report stays pending)", pending, failID)
	}

	// --- Run 2: retries only N; creates exactly one issue and does not touch 1..N-1. ---
	createdBeforeRun2 := len(mc.created)
	run2, _ := manager.ListPending(ctx)
	if !slices.Equal(run2, []string{failID}) {
		t.Fatalf("run2 pending = %v, want only the failed report [%s]", run2, failID)
	}
	if err := pub.Publish(ctx, run2); err != nil {
		t.Fatalf("run2 Publish (retry of %s): %v", failID, err)
	}
	if newIssues := len(mc.created) - createdBeforeRun2; newIssues != 1 {
		t.Errorf("run2 created %d new issues, want exactly 1 (only report N retried)", newIssues)
	}
	// The one new issue was for N.
	last := mc.created[len(mc.created)-1]
	if !strings.Contains(last.body, failID) {
		t.Errorf("run2's new issue was not for the failed report %s: %q", failID, last.title)
	}
	// Everything published, nothing pending, and no duplicates: exactly N published
	// objects and exactly N issues created across the two runs.
	if pending, _ := manager.ListPending(ctx); len(pending) != 0 {
		t.Errorf("after run2 ListPending = %v, want empty", pending)
	}
	if got := publishedCount(t, store); got != len(ids) {
		t.Errorf("after run2 published objects = %d, want %d", got, len(ids))
	}
	if len(mc.created) != len(ids) {
		t.Errorf("total issues created across both runs = %d, want %d (no duplication of 1..N-1)", len(mc.created), len(ids))
	}
}

// TestMarkPublishedIdempotentAfterPublish covers the idempotency acceptance:
// MarkPublished on an already-published report (here, one the publish hook already
// marked) is a no-op success and does not create a second published object.
func TestMarkPublishedIdempotentAfterPublish(t *testing.T) {
	ctx := context.Background()
	kr := mustKeyring(t)
	store := storage.NewMemoryStore()
	const id = "20260101T000000-aaaa"
	putPending(t, store, kr, id)
	manager := lifecycle.New(store)
	mc := &mockCreator{}
	pub := newPublisher(mc, kr, manager, WithMarkPublished(manager))

	ids, _ := manager.ListPending(ctx)
	if err := pub.Publish(ctx, ids); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// The publish hook already transitioned it to published. A redundant, explicit
	// MarkPublished must succeed (idempotent) and leave exactly one published object.
	if err := manager.MarkPublished(ctx, id); err != nil {
		t.Errorf("redundant MarkPublished = %v, want nil (idempotent no-op)", err)
	}
	if pending, _ := manager.ListPending(ctx); len(pending) != 0 {
		t.Errorf("ListPending = %v, want empty", pending)
	}
	if got := publishedCount(t, store); got != 1 {
		t.Errorf("published objects = %d, want exactly 1 (no duplicate from the redundant mark)", got)
	}
}

// flakyMarker wraps a real Manager and fails MarkPublished for selected ids, to
// exercise the honest mark-failure edge case (issue created, mark failed).
type flakyMarker struct {
	m    *lifecycle.Manager
	fail map[string]bool
}

func (f *flakyMarker) MarkPublished(ctx context.Context, id string) error {
	if f.fail[id] {
		return errors.New("r2: put published object failed")
	}
	return f.m.MarkPublished(ctx, id)
}

// TestMarkPublishedFailureSurfacedLoggedAndRepublishes documents the honest edge
// case: if the issue is created (201) but MarkPublished then fails, the failure is
// (a) surfaced so the run is recorded failed, (b) logged loudly with the duplicate
// risk, and (c) leaves the report pending — so once the mark backend recovers, the
// next run re-publishes it as a DUPLICATE. This is the residual risk WithMarkPublished
// notes; MarkPublished's idempotency bounds it to at most one duplicate.
func TestMarkPublishedFailureSurfacedLoggedAndRepublishes(t *testing.T) {
	ctx := context.Background()
	kr := mustKeyring(t)
	store := storage.NewMemoryStore()
	const id = "20260101T000000-aaaa"
	putPending(t, store, kr, id)
	manager := lifecycle.New(store)
	marker := &flakyMarker{m: manager, fail: map[string]bool{id: true}}

	var logs []string
	mc := &mockCreator{}
	pub := newPublisher(mc, kr, manager,
		WithMarkPublished(marker),
		WithLogger(func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }),
	)

	// --- Run 1: create succeeds, the mark fails. ---
	run1, _ := manager.ListPending(ctx)
	if err := pub.Publish(ctx, run1); err == nil {
		t.Fatal("expected the mark-published failure to be surfaced")
	}
	if len(mc.created) != 1 {
		t.Errorf("created %d issues, want 1 (create succeeded before the mark failed)", len(mc.created))
	}
	// The report stays pending (the mark failed) -> it will be retried next run.
	if pending, _ := manager.ListPending(ctx); !slices.Contains(pending, id) {
		t.Errorf("report should remain pending after a mark failure; pending=%v", pending)
	}
	// A loud, specific log names the report and the duplicate risk.
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, id) || !strings.Contains(strings.ToUpper(joined), "DUPLICATE") {
		t.Errorf("expected a loud mark-failure log naming the report and the DUPLICATE risk; got:\n%s", joined)
	}

	// --- Run 2: the mark backend recovers; the still-pending report re-publishes,
	// producing the DUPLICATE issue the note warns about (idempotency bounds it to
	// one). This asserts the honest behaviour rather than an idealized one. ---
	marker.fail[id] = false
	run2, _ := manager.ListPending(ctx)
	if err := pub.Publish(ctx, run2); err != nil {
		t.Fatalf("run2 Publish: %v", err)
	}
	if len(mc.created) != 2 {
		t.Errorf("created %d issues total, want 2 (the documented duplicate on retry)", len(mc.created))
	}
	if pending, _ := manager.ListPending(ctx); len(pending) != 0 {
		t.Errorf("after recovery ListPending = %v, want empty (mark converged)", pending)
	}
	if got := publishedCount(t, store); got != 1 {
		t.Errorf("published objects = %d, want 1", got)
	}
}
