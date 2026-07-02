package publish

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/crypto"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/ingest"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/lifecycle"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/schedule"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/storage"
)

// The real Publisher must satisfy the schedule.Publisher seam it replaces.
var _ schedule.Publisher = (*Publisher)(nil)

// --- helpers ---

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

func seal(t *testing.T, kr *crypto.Keyring, plaintext []byte) []byte {
	t.Helper()
	frame, err := crypto.Seal(kr, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return frame
}

// fakeGetter is an in-memory PendingGetter (the GetPending seam) keyed by id.
type fakeGetter struct {
	frames map[string][]byte
	errs   map[string]error
}

func (f *fakeGetter) GetPending(_ context.Context, id string) ([]byte, error) {
	if e := f.errs[id]; e != nil {
		return nil, e
	}
	frame, ok := f.frames[id]
	if !ok {
		return nil, errors.New("fakeGetter: no frame for " + id)
	}
	return frame, nil
}

// mockCreator is an issueCreator that records created issues and can be scripted
// to fail, without any HTTP. It exercises Publisher orchestration in isolation.
type mockCreator struct {
	mu          sync.Mutex
	ensureErr   error
	ensureCalls int
	created     []createRec
	createFn    func(title, body string, labels []string) (CreatedIssue, error)
}

type createRec struct {
	title, body string
	labels      []string
}

func (m *mockCreator) EnsureLabels(_ context.Context, _ []Label) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureCalls++
	return m.ensureErr
}

func (m *mockCreator) CreateIssue(_ context.Context, title, body string, labels []string) (CreatedIssue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createFn != nil {
		iss, err := m.createFn(title, body, labels)
		if err == nil {
			m.created = append(m.created, createRec{title, body, labels})
		}
		return iss, err
	}
	n := len(m.created) + 1
	m.created = append(m.created, createRec{title, body, labels})
	return CreatedIssue{Number: n, HTMLURL: fmt.Sprintf("https://github.com/o/r/issues/%d", n)}, nil
}

func recorder() (func(context.Context, string) error, func() []string) {
	var mu sync.Mutex
	var ids []string
	fn := func(_ context.Context, id string) error {
		mu.Lock()
		defer mu.Unlock()
		ids = append(ids, id)
		return nil
	}
	get := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), ids...)
	}
	return fn, get
}

func sampleReport(id string) ingest.Report {
	return ingest.Report{
		AppVersion: "1.4.2 (142)",
		Platform:   "android",
		OSVersion:  "Android 14",
		Device:     "Pixel 7",
		Report:     "crash for " + id,
	}
}

// --- tests ---

// TestPublishOneLabeledIssuePerReport is the ticket's core acceptance: N pending
// encrypted reports + a test keyring, run through the REAL GitHub client (against
// an httptest mock), produce exactly N well-formed, labeled issues and call
// onPublished once per success.
func TestPublishOneLabeledIssuePerReport(t *testing.T) {
	kr := mustKeyring(t)
	ids := []string{"id-1", "id-2", "id-3"}
	frames := map[string][]byte{}
	for _, id := range ids {
		frames[id] = seal(t, kr, reportJSON(t, sampleReport(id)))
	}

	g := &ghServer{}
	srv := httptest.NewServer(g)
	defer srv.Close()
	client := testClient(srv.URL, newFakeClock())

	onPub, published := recorder()
	pub := New(client, kr, &fakeGetter{frames: frames}, WithOnPublished(onPub))

	if err := pub.Publish(context.Background(), ids); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if len(g.createdIssues) != len(ids) {
		t.Fatalf("created %d issues, want %d", len(g.createdIssues), len(ids))
	}
	wantLabels := LabelNames(DefaultLabels)
	for i, iss := range g.createdIssues {
		if !slices.Equal(iss.Labels, wantLabels) {
			t.Errorf("issue %d labels = %v, want %v", i, iss.Labels, wantLabels)
		}
		if iss.Title == "" || iss.Body == "" {
			t.Errorf("issue %d not well-formed: %+v", i, iss)
		}
	}
	// The three labels are ensured once per run (idempotent create-or-ignore).
	if g.labelAttempts != len(DefaultLabels) {
		t.Errorf("label POSTs = %d, want %d", g.labelAttempts, len(DefaultLabels))
	}
	// onPublished called for each success, in order.
	if got := published(); !slices.Equal(got, ids) {
		t.Errorf("onPublished ids = %v, want %v", got, ids)
	}
}

// TestPublishRespectsPerRunCap: given more than the cap, exactly cap issues are
// created (oldest-first) and the rest are left for the next run (ADR #6 §3.1).
func TestPublishRespectsPerRunCap(t *testing.T) {
	kr := mustKeyring(t)
	const n = DefaultMaxPerRun + 5
	ids := make([]string, n)
	frames := map[string][]byte{}
	for i := range ids {
		id := fmt.Sprintf("id-%03d", i)
		ids[i] = id
		frames[id] = seal(t, kr, reportJSON(t, sampleReport(id)))
	}

	mc := &mockCreator{}
	onPub, published := recorder()
	pub := newPublisher(mc, kr, &fakeGetter{frames: frames}, WithOnPublished(onPub))

	if err := pub.Publish(context.Background(), ids); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(mc.created) != DefaultMaxPerRun {
		t.Errorf("created %d issues, want the cap %d", len(mc.created), DefaultMaxPerRun)
	}
	if got := len(published()); got != DefaultMaxPerRun {
		t.Errorf("onPublished called %d times, want the cap %d", got, DefaultMaxPerRun)
	}
	// The published ids are the oldest (first) DefaultMaxPerRun.
	if got := published(); !slices.Equal(got, ids[:DefaultMaxPerRun]) {
		t.Errorf("published set is not the oldest %d ids", DefaultMaxPerRun)
	}
}

// TestPublishIsolatesDecryptFailure: a report that fails to decrypt is isolated
// and surfaced, the others still publish, and onPublished is NOT called for it.
func TestPublishIsolatesDecryptFailure(t *testing.T) {
	kr := mustKeyring(t)
	wrongKr := mustKeyring(t) // different key material -> ErrAuth on Open

	ids := []string{"good-1", "bad", "good-2"}
	frames := map[string][]byte{
		"good-1": seal(t, kr, reportJSON(t, sampleReport("good-1"))),
		"bad":    seal(t, wrongKr, reportJSON(t, sampleReport("bad"))), // sealed under the wrong key
		"good-2": seal(t, kr, reportJSON(t, sampleReport("good-2"))),
	}

	mc := &mockCreator{}
	onPub, published := recorder()
	pub := newPublisher(mc, kr, &fakeGetter{frames: frames}, WithOnPublished(onPub))

	err := pub.Publish(context.Background(), ids)
	if err == nil {
		t.Fatal("expected a surfaced (non-nil) error for the decrypt failure")
	}
	if !strings.Contains(err.Error(), "bad") || !strings.Contains(err.Error(), "decrypt") {
		t.Errorf("error should name the failed report and reason: %v", err)
	}
	if len(mc.created) != 2 {
		t.Errorf("created %d issues, want 2 (the decrypt failure isolated)", len(mc.created))
	}
	if got := published(); !slices.Equal(got, []string{"good-1", "good-2"}) {
		t.Errorf("onPublished ids = %v, want the two good reports only", got)
	}
}

// TestPublishIsolatesCreateFailure: a persistent create failure on one report
// isolates it (others publish) and does NOT call onPublished for it.
func TestPublishIsolatesCreateFailure(t *testing.T) {
	kr := mustKeyring(t)
	ids := []string{"id-1", "id-2", "id-3"}
	frames := map[string][]byte{}
	for _, id := range ids {
		frames[id] = seal(t, kr, reportJSON(t, sampleReport(id)))
	}

	calls := 0
	mc := &mockCreator{createFn: func(_, _ string, _ []string) (CreatedIssue, error) {
		calls++
		if calls == 2 { // the second report fails permanently (retries exhausted)
			return CreatedIssue{}, errors.New("github: create issue: gave up after 5 attempts")
		}
		return CreatedIssue{Number: calls, HTMLURL: fmt.Sprintf("u/%d", calls)}, nil
	}}
	onPub, published := recorder()
	pub := newPublisher(mc, kr, &fakeGetter{frames: frames}, WithOnPublished(onPub))

	err := pub.Publish(context.Background(), ids)
	if err == nil {
		t.Fatal("expected a surfaced error for the create failure")
	}
	if !strings.Contains(err.Error(), "id-2") {
		t.Errorf("error should name the failed report id-2: %v", err)
	}
	if len(mc.created) != 2 {
		t.Errorf("created %d issues, want 2 (id-1 and id-3)", len(mc.created))
	}
	if got := published(); slices.Contains(got, "id-2") {
		t.Errorf("onPublished must not be called for the failed report; got %v", got)
	}
	if got := published(); !slices.Equal(got, []string{"id-1", "id-3"}) {
		t.Errorf("onPublished ids = %v, want id-1 and id-3", got)
	}
}

// TestPublishSurfacesOnPublishedError: if the #15 mark-published hook errors, the
// issue was still created but the failure is surfaced (so #15 can reconcile) and
// the rest of the batch is unaffected.
func TestPublishSurfacesOnPublishedError(t *testing.T) {
	kr := mustKeyring(t)
	ids := []string{"id-1", "id-2"}
	frames := map[string][]byte{}
	for _, id := range ids {
		frames[id] = seal(t, kr, reportJSON(t, sampleReport(id)))
	}

	mc := &mockCreator{}
	pub := newPublisher(mc, kr, &fakeGetter{frames: frames},
		WithOnPublished(func(_ context.Context, id string) error {
			if id == "id-1" {
				return errors.New("mark published failed")
			}
			return nil
		}))

	err := pub.Publish(context.Background(), ids)
	if err == nil {
		t.Fatal("expected the onPublished error to be surfaced")
	}
	if !strings.Contains(err.Error(), "id-1") {
		t.Errorf("error should name the failing report: %v", err)
	}
	// Both issues were created (the hook runs only after a confirmed create).
	if len(mc.created) != 2 {
		t.Errorf("created %d issues, want 2 (the hook failure does not undo creation)", len(mc.created))
	}
}

// TestPublishEmptyBatchNoop: an empty batch does nothing (not even label ensure).
func TestPublishEmptyBatchNoop(t *testing.T) {
	kr := mustKeyring(t)
	mc := &mockCreator{}
	pub := newPublisher(mc, kr, &fakeGetter{})
	if err := pub.Publish(context.Background(), nil); err != nil {
		t.Fatalf("Publish(nil): %v", err)
	}
	if mc.ensureCalls != 0 || len(mc.created) != 0 {
		t.Errorf("empty batch did work: ensureCalls=%d created=%d", mc.ensureCalls, len(mc.created))
	}
}

// TestPublisherWorksWithLifecycleManager proves *lifecycle.Manager satisfies the
// PendingGetter seam and the whole pipeline runs end to end off the real store.
func TestPublisherWorksWithLifecycleManager(t *testing.T) {
	ctx := context.Background()
	kr := mustKeyring(t)
	store := storage.NewMemoryStore()
	ids := []string{"20260101T000000-aaaa", "20260102T000000-bbbb"}
	for _, id := range ids {
		frame := seal(t, kr, reportJSON(t, sampleReport(id)))
		if err := store.Put(ctx, storage.ReportKey(storage.StatusPending, id), frame); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	manager := lifecycle.New(store)
	pending, err := manager.ListPending(ctx)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}

	g := &ghServer{}
	srv := httptest.NewServer(g)
	defer srv.Close()
	client := testClient(srv.URL, newFakeClock())

	onPub, published := recorder()
	pub := New(client, kr, manager, WithOnPublished(onPub))

	if err := pub.Publish(ctx, pending); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(g.createdIssues) != len(ids) {
		t.Errorf("created %d issues, want %d", len(g.createdIssues), len(ids))
	}
	if got := published(); !slices.Equal(got, pending) {
		t.Errorf("onPublished ids = %v, want %v", got, pending)
	}
}

func TestParseRepo(t *testing.T) {
	owner, repo, err := ParseRepo("JMR-dev/LibreMail")
	if err != nil || owner != "JMR-dev" || repo != "LibreMail" {
		t.Errorf("ParseRepo ok case = (%q,%q,%v)", owner, repo, err)
	}
	for _, bad := range []string{"", "noslash", "a/b/c", "/LibreMail", "JMR-dev/"} {
		if _, _, err := ParseRepo(bad); err == nil {
			t.Errorf("ParseRepo(%q) = nil error, want failure", bad)
		}
	}
}
