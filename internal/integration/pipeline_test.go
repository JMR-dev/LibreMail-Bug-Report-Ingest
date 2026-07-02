// Package integration wires the LibreMail bug-report ingest Worker's REAL
// components together and exercises the FULL pipeline end to end on the host,
// with no TinyGo, miniflare, or network dependency.
//
// The per-ticket suites already unit-test each stage in isolation (ingest #7,
// scrub #8, crypto #9, storage #9, lifecycle #10, admin removal #11, schedule
// #13, publish #14, mark-published #15). These tests tie those stages together
// through the exact seams the deployed Worker (worker/) and the dev server
// (cmd/devserver) use, so a regression in how the stages compose is caught even
// when every unit test still passes:
//
//   - the real http.Handler (handler.New: ingest + admin) over a real loopback
//     httptest.Server, driven with a real net/http client;
//   - the real scrub -> encrypt -> store Sink (storage.NewSink) backed by a
//     storage.MemoryStore, with a real AES-256-GCM host keyring (internal/crypto);
//   - the real lifecycle.Manager over that same store (so an ingested report is
//     immediately listable/removable by the admin API and publishable by the job);
//   - the real internal/publish Publisher driving the real GitHub *Client against
//     a mock GitHub REST API (an httptest server implementing POST /labels and
//     POST /issues) — reusing #14's "point the client at an httptest server" seam;
//   - the real schedule.Run Friday-17:00-Central gate.
//
// Because this is a build-tag-free Go test, CI (#3, .github/workflows/ci.yml)
// runs it on every PR via `go test ./...`; no CI change is needed.
//
// All wall-clock behaviour is removed (a virtual clock plus zero request
// spacing on the GitHub client), so the suite is deterministic and fast.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/crypto"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/handler"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/ingest"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/lifecycle"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/publish"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/schedule"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/scrub"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/storage"
)

// adminToken is the shared-secret bearer token the wired admin API authenticates
// against (as ADMIN_TOKEN would in the dev server / Worker).
const adminToken = "integration-admin-secret"

// fridayFireInstant is a Cron Trigger fire that IS 17:00 America/Chicago on a
// Friday: 2026-07-10 is a Friday in CDT (UTC-5), so 22:00 UTC == 17:00 Central.
// It is the exact instant the schedule package's own tests use for the gate.
var fridayFireInstant = time.Date(2026, time.July, 10, 22, 0, 0, 0, time.UTC)

// piiJWT is a syntactically valid JWT (eyJ-anchored). It is the same token used
// by the scrub unit tests, so its redaction to a placeholder is already proven.
const piiJWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlX3ZhbHVl"

// piiSecrets are the sensitive substrings embedded in reportWithPII. After the
// pipeline runs, none of these may survive into storage (encrypted or not) or
// into a published GitHub issue.
var piiSecrets = []string{
	"alice@example.com",    // email        -> [REDACTED_EMAIL]
	piiJWT,                 // bearer token -> [REDACTED_AUTH]
	"AKIAIOSFODNN7EXAMPLE", // AWS key id   -> [REDACTED_TOKEN]
	"p@ssw0rd!",            // secret value -> [REDACTED_TOKEN]
	"203.0.113.7",          // IPv4         -> [REDACTED_IP]
	"2001:db8::1",          // IPv6         -> [REDACTED_IP]
}

// piiPlaceholders are the scrub placeholders the redacted body must contain,
// one per PII category present in reportWithPII.
var piiPlaceholders = []string{
	scrub.PlaceholderEmail,
	scrub.PlaceholderAuth,
	scrub.PlaceholderToken,
	scrub.PlaceholderIP,
}

// reportWithPII builds a well-formed v1 report whose free-text field carries one
// example of every PII category the scrubber handles, plus a stack-trace line
// that must survive (an over-redaction guard). The bytes are exactly what the
// app would POST to /v1/reports.
func reportWithPII(t *testing.T) []byte {
	t.Helper()
	rep := ingest.Report{
		AppVersion: "1.4.2 (142)",
		Platform:   "android",
		OSVersion:  "Android 14",
		Device:     "Pixel 7",
		Report: strings.Join([]string{
			"User contact: alice@example.com",
			"Session: Authorization: Bearer " + piiJWT,
			"Env: AWS_KEY=AKIAIOSFODNN7EXAMPLE password=p@ssw0rd!",
			"Network: connected from 203.0.113.7 via gateway 2001:db8::1",
			"Stack: at com.example.app.Main.run(Main.java:99)",
		}, "\n"),
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	return raw
}

// ---------------------------------------------------------------------------
// Pipeline harness: the same wiring as cmd/devserver and worker/buildPublish.
// ---------------------------------------------------------------------------

type pipeline struct {
	keyring *crypto.Keyring
	store   *storage.MemoryStore
	manager *lifecycle.Manager
	server  *httptest.Server // the real http.Handler over loopback
}

// newPipeline assembles the real handler (ingest + admin) over a real scrub +
// encrypt + store Sink and a lifecycle.Manager sharing one MemoryStore, exactly
// as cmd/devserver does. A real AES-256 host keyring encrypts at rest.
func newPipeline(t *testing.T) *pipeline {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyring, err := crypto.NewKeyring(1, map[uint16][]byte{1: key})
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	store := storage.NewMemoryStore()
	sink := storage.NewSink(store, keyring) // scrub -> seal -> put under reports/pending/<id>
	manager := lifecycle.New(store)
	h := handler.New(sink, handler.NewManagerBackend(manager, adminToken))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &pipeline{keyring: keyring, store: store, manager: manager, server: srv}
}

// newPublisher builds the real publish.Publisher driving the real GitHub client
// against gh (a mock GitHub REST server), with cross-run de-dup wired to the
// pipeline's lifecycle.Manager (#15), mirroring worker/buildPublish. The client
// uses a virtual clock and zero spacing so no real time passes.
func (p *pipeline) newPublisher(t *testing.T, gh *mockGitHub) *publish.Publisher {
	t.Helper()
	srv := httptest.NewServer(gh)
	t.Cleanup(srv.Close)
	fc := newFakeClock()
	client := publish.NewClient("test-token", "o", "r",
		publish.WithBaseURL(srv.URL),
		publish.WithClock(fc.now, fc.sleep),
		publish.WithSpacing(0),
	)
	return publish.New(client, p.keyring, p.manager,
		publish.WithMarkPublished(p.manager),
		publish.WithLogger(t.Logf), // route publish logs to the test log (shown only on -v/failure)
	)
}

// pendingIDs returns the ids currently pending.
func (p *pipeline) pendingIDs(t *testing.T) []string {
	t.Helper()
	ids, err := p.manager.ListPending(context.Background())
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	return ids
}

// keysUnder returns the object keys stored under a status prefix.
func (p *pipeline) keysUnder(t *testing.T, s storage.Status) []string {
	t.Helper()
	keys, err := p.store.List(context.Background(), storage.StatusPrefix(s))
	if err != nil {
		t.Fatalf("List %s: %v", s, err)
	}
	return keys
}

// ---------------------------------------------------------------------------
// HTTP helpers (real net/http client -> real loopback server).
// ---------------------------------------------------------------------------

type httpResult struct {
	status int
	header http.Header
	body   map[string]any
	raw    string
}

// do issues one request against the wired handler and reads the whole response.
func (p *pipeline) do(t *testing.T, method, path, contentType, bearer string, body []byte) httpResult {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, p.server.URL+path, r)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, path, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	res := httpResult{status: resp.StatusCode, header: resp.Header.Clone(), raw: string(raw)}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &res.body)
	}
	return res
}

func (p *pipeline) ingest(t *testing.T, body []byte) httpResult {
	return p.do(t, http.MethodPost, "/v1/reports", "application/json", "", body)
}

func (p *pipeline) adminList(t *testing.T, bearer string) httpResult {
	return p.do(t, http.MethodGet, "/v1/admin/reports", "", bearer, nil)
}

func (p *pipeline) adminRemove(t *testing.T, id, bearer string) httpResult {
	return p.do(t, http.MethodPost, "/v1/admin/reports/"+id+"/remove", "", bearer, nil)
}

// reportsField extracts the "reports" array from an admin list response.
func reportsField(t *testing.T, res httpResult) []string {
	t.Helper()
	arr, ok := res.body["reports"].([]any)
	if !ok {
		t.Fatalf("admin list has no reports array: %q", res.raw)
	}
	out := make([]string, len(arr))
	for i, v := range arr {
		out[i], _ = v.(string)
	}
	return out
}

// ---------------------------------------------------------------------------
// Mock GitHub REST API (POST /labels, POST /issues).
// ---------------------------------------------------------------------------

type issueRec struct {
	Title  string
	Body   string
	Labels []string
}

// mockGitHub is a minimal, thread-safe stand-in for the GitHub REST API. It
// accepts the two POSTs the publisher makes and records what it received, always
// answering 201 so every publish is a confirmed create.
type mockGitHub struct {
	mu      sync.Mutex
	labels  []string
	issues  []issueRec
	nextNum int
}

func (m *mockGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case strings.HasSuffix(r.URL.Path, "/labels") && r.Method == http.MethodPost:
		var lr struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&lr)
		m.labels = append(m.labels, lr.Name)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	case strings.HasSuffix(r.URL.Path, "/issues") && r.Method == http.MethodPost:
		var ir struct {
			Title  string   `json:"title"`
			Body   string   `json:"body"`
			Labels []string `json:"labels"`
		}
		_ = json.NewDecoder(r.Body).Decode(&ir)
		m.nextNum++
		m.issues = append(m.issues, issueRec{Title: ir.Title, Body: ir.Body, Labels: ir.Labels})
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"number":%d,"html_url":"https://github.com/o/r/issues/%d"}`, m.nextNum, m.nextNum)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (m *mockGitHub) issueCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.issues)
}

func (m *mockGitHub) issueSnapshot() []issueRec {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]issueRec(nil), m.issues...)
}

func (m *mockGitHub) labelSnapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.labels...)
}

// fakeClock is a virtual clock whose time only advances on Sleep, so the GitHub
// client's spacing/backoff never incurs real delay.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()} }

func (f *fakeClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) sleep(_ context.Context, d time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if d > 0 {
		f.t = f.t.Add(d)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestIngestScrubsEncryptsAndStores is the end-to-end proof that
// ingest -> scrub -> encrypt -> store works as one unit: a POST with PII is
// accepted, the object at rest is AES-256-GCM ciphertext that leaks neither the
// PII nor even the scrubbed placeholder text, and decrypting it yields the fully
// scrubbed body (PII gone, placeholders present).
func TestIngestScrubsEncryptsAndStores(t *testing.T) {
	ctx := context.Background()
	p := newPipeline(t)
	raw := reportWithPII(t)

	res := p.ingest(t, raw)
	if res.status != http.StatusAccepted {
		t.Fatalf("POST /v1/reports = %d, want 202 (body=%q)", res.status, res.raw)
	}
	if got, _ := res.body["status"].(string); got != "accepted" {
		t.Errorf("accept body status = %q, want accepted", got)
	}

	// Exactly one object, pending, encrypted at rest.
	ids := p.pendingIDs(t)
	if len(ids) != 1 {
		t.Fatalf("pending after one ingest = %d, want 1", len(ids))
	}
	if n := p.store.Len(); n != 1 {
		t.Fatalf("store holds %d objects, want 1", n)
	}
	frame, err := p.manager.GetPending(ctx, ids[0])
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}

	// The stored bytes are a real crypto frame (magic + active key id), not the
	// plaintext, and contain neither the PII nor the scrubbed placeholder text —
	// so the object is genuinely encrypted, not merely scrubbed.
	if !bytes.HasPrefix(frame, []byte(crypto.Magic)) {
		t.Errorf("stored object is not a crypto frame (no %q magic)", crypto.Magic)
	}
	if id, err := crypto.KeyID(frame); err != nil || id != p.keyring.Active() {
		t.Errorf("stored frame key id = %d (err=%v), want active %d", id, err, p.keyring.Active())
	}
	for _, secret := range piiSecrets {
		if bytes.Contains(frame, []byte(secret)) {
			t.Errorf("ENCRYPTED object leaks PII %q", secret)
		}
	}
	if bytes.Contains(frame, []byte(scrub.PlaceholderEmail)) {
		t.Error("encrypted object exposes cleartext placeholder text; it must be ciphertext")
	}

	// Decrypt and prove the plaintext is the scrubbed body.
	plain, err := crypto.Open(p.keyring, frame)
	if err != nil {
		t.Fatalf("Open stored frame: %v", err)
	}
	if !bytes.Equal(plain, scrub.Scrub(raw)) {
		t.Errorf("decrypted body is not the scrubbed payload:\n got  = %q\n want = %q", plain, scrub.Scrub(raw))
	}
	for _, secret := range piiSecrets {
		if bytes.Contains(plain, []byte(secret)) {
			t.Errorf("decrypted (scrubbed) body still leaks PII %q", secret)
		}
	}
	for _, ph := range piiPlaceholders {
		if !bytes.Contains(plain, []byte(ph)) {
			t.Errorf("decrypted body missing expected placeholder %q", ph)
		}
	}
	// Over-redaction guard: non-sensitive diagnostic text must survive.
	if !bytes.Contains(plain, []byte("com.example.app.Main.run")) {
		t.Error("scrub over-redacted: the stack-trace line did not survive")
	}
}

// TestPendingListedThenRemovedViaAdmin proves the admin API (#11) operates over
// the same store the ingest path writes: a freshly ingested report is pending
// and listable (only when authenticated), and an admin remove transitions it to
// removed so it drops from the pending set.
func TestPendingListedThenRemovedViaAdmin(t *testing.T) {
	p := newPipeline(t)

	if res := p.ingest(t, reportWithPII(t)); res.status != http.StatusAccepted {
		t.Fatalf("ingest = %d, want 202", res.status)
	}
	ids := p.pendingIDs(t)
	if len(ids) != 1 {
		t.Fatalf("pending = %d, want 1", len(ids))
	}
	id := ids[0]

	// Unauthenticated list is refused (fail-closed) with a Bearer challenge.
	if res := p.adminList(t, ""); res.status != http.StatusUnauthorized {
		t.Errorf("unauth list = %d, want 401", res.status)
	} else if ch := res.header.Get("WWW-Authenticate"); ch != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want Bearer", ch)
	}

	// Authenticated list returns exactly the pending id.
	res := p.adminList(t, adminToken)
	if res.status != http.StatusOK {
		t.Fatalf("authed list = %d, want 200 (body=%q)", res.status, res.raw)
	}
	if got := reportsField(t, res); !slices.Equal(got, []string{id}) {
		t.Errorf("admin list = %v, want [%s]", got, id)
	}

	// Remove it; it must report removed and leave the pending set.
	rm := p.adminRemove(t, id, adminToken)
	if rm.status != http.StatusOK {
		t.Fatalf("remove = %d, want 200 (body=%q)", rm.status, rm.raw)
	}
	if s, _ := rm.body["status"].(string); s != "removed" {
		t.Errorf("remove status field = %q, want removed", s)
	}
	if got := reportsField(t, p.adminList(t, adminToken)); len(got) != 0 {
		t.Errorf("pending after remove = %v, want empty", got)
	}
	if len(p.pendingIDs(t)) != 0 {
		t.Error("report still pending after admin remove")
	}
	// It now lives under the removed prefix (excluded from publishing).
	if got := p.keysUnder(t, storage.StatusRemoved); !slices.Equal(got, []string{storage.ReportKey(storage.StatusRemoved, id)}) {
		t.Errorf("removed keys = %v, want the single removed report", got)
	}
}

// TestCronPublishesPendingAndDedups is the headline scenario: ingest several
// reports with PII, then the Friday-17:00-Central cron lists pending, publishes
// one labeled GitHub issue per report (via the real client + mock GitHub) with
// PII scrubbed out of the issue body, and marks each published so the pending
// set empties. A second run over the now-empty set creates NO new issues
// (cross-run de-dup), and a freshly ingested report published on a later run is
// the only new issue (de-dup is selective, not "publish nothing forever").
func TestCronPublishesPendingAndDedups(t *testing.T) {
	ctx := context.Background()
	p := newPipeline(t)

	const n = 3
	for i := 0; i < n; i++ {
		if res := p.ingest(t, reportWithPII(t)); res.status != http.StatusAccepted {
			t.Fatalf("ingest %d = %d, want 202", i, res.status)
		}
	}
	if got := len(p.pendingIDs(t)); got != n {
		t.Fatalf("pending before publish = %d, want %d", got, n)
	}

	gh := &mockGitHub{}
	publisher := p.newPublisher(t, gh)

	// --- Run 1: the gate fires, all n reports publish and are marked published. ---
	ran, err := schedule.Run(ctx, fridayFireInstant, p.manager, publisher)
	if err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if !ran {
		t.Fatal("run 1 gate did not fire at Friday 17:00 Central")
	}
	if got := gh.issueCount(); got != n {
		t.Fatalf("run 1 created %d issues, want %d", got, n)
	}

	// Every issue carries the three ADR #6 labels and a PII-free, scrubbed body.
	wantLabels := publish.LabelNames(publish.DefaultLabels)
	for i, iss := range gh.issueSnapshot() {
		if !slices.Equal(iss.Labels, wantLabels) {
			t.Errorf("issue %d labels = %v, want %v", i, iss.Labels, wantLabels)
		}
		if iss.Title == "" || iss.Body == "" {
			t.Errorf("issue %d is not well-formed: %+v", i, iss)
		}
		if !strings.Contains(iss.Body, scrub.PlaceholderEmail) {
			t.Errorf("issue %d body is not the scrubbed report (no placeholder)", i)
		}
		for _, secret := range piiSecrets {
			if strings.Contains(iss.Body, secret) {
				t.Errorf("issue %d body leaks PII %q to GitHub", i, secret)
			}
		}
	}
	// The three labels were ensured (create-or-ignore) once this run.
	if got := gh.labelSnapshot(); !slices.Equal(got, wantLabels) {
		t.Errorf("ensured labels = %v, want %v", got, wantLabels)
	}
	// All published, nothing pending.
	if got := len(p.pendingIDs(t)); got != 0 {
		t.Errorf("pending after run 1 = %d, want 0 (all marked published)", got)
	}
	if got := len(p.keysUnder(t, storage.StatusPublished)); got != n {
		t.Errorf("published objects = %d, want %d", got, n)
	}

	// --- Run 2: nothing pending -> no new issues (end-to-end de-dup). ---
	ran, err = schedule.Run(ctx, fridayFireInstant, p.manager, publisher)
	if err != nil {
		t.Fatalf("run 2: %v", err)
	}
	if !ran {
		t.Fatal("run 2 gate did not fire")
	}
	if got := gh.issueCount(); got != n {
		t.Errorf("run 2 created new issues (total %d), want no duplication (still %d)", got, n)
	}

	// --- A new report ingested later publishes exactly once on the next run. ---
	if res := p.ingest(t, reportWithPII(t)); res.status != http.StatusAccepted {
		t.Fatalf("late ingest = %d, want 202", res.status)
	}
	ran, err = schedule.Run(ctx, fridayFireInstant, p.manager, publisher)
	if err != nil {
		t.Fatalf("run 3: %v", err)
	}
	if !ran {
		t.Fatal("run 3 gate did not fire")
	}
	if got := gh.issueCount(); got != n+1 {
		t.Errorf("run 3 total issues = %d, want %d (only the new report published)", got, n+1)
	}
	if got := len(p.pendingIDs(t)); got != 0 {
		t.Errorf("pending after run 3 = %d, want 0", got)
	}
	if got := len(p.keysUnder(t, storage.StatusPublished)); got != n+1 {
		t.Errorf("published objects after run 3 = %d, want %d", got, n+1)
	}
}

// TestRemovedReportIsNotPublished ties the admin removal path (#11) to the
// publish job (#14): a report a maintainer pulls before the Friday run never
// becomes a GitHub issue, while the reports left pending do.
func TestRemovedReportIsNotPublished(t *testing.T) {
	ctx := context.Background()
	p := newPipeline(t)

	for i := 0; i < 2; i++ {
		if res := p.ingest(t, reportWithPII(t)); res.status != http.StatusAccepted {
			t.Fatalf("ingest %d = %d, want 202", i, res.status)
		}
	}
	ids := p.pendingIDs(t)
	if len(ids) != 2 {
		t.Fatalf("pending = %d, want 2", len(ids))
	}
	removedID, keptID := ids[0], ids[1]

	if rm := p.adminRemove(t, removedID, adminToken); rm.status != http.StatusOK {
		t.Fatalf("remove = %d, want 200 (body=%q)", rm.status, rm.raw)
	}

	gh := &mockGitHub{}
	publisher := p.newPublisher(t, gh)
	if _, err := schedule.Run(ctx, fridayFireInstant, p.manager, publisher); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Exactly one issue, and it is the kept report — the removed one never
	// appears (the issue body carries the report id, so we can check by id).
	issues := gh.issueSnapshot()
	if len(issues) != 1 {
		t.Fatalf("created %d issues, want 1 (removed report excluded)", len(issues))
	}
	if !strings.Contains(issues[0].Body, keptID) {
		t.Errorf("published issue is not the kept report %s", keptID)
	}
	for _, iss := range issues {
		if strings.Contains(iss.Body, removedID) {
			t.Errorf("removed report %s was published as an issue", removedID)
		}
	}
	// The removed report is still under the removed prefix, never published.
	if got := p.keysUnder(t, storage.StatusRemoved); !slices.Equal(got, []string{storage.ReportKey(storage.StatusRemoved, removedID)}) {
		t.Errorf("removed keys = %v, want the single removed report", got)
	}
	if got := p.keysUnder(t, storage.StatusPublished); !slices.Equal(got, []string{storage.ReportKey(storage.StatusPublished, keptID)}) {
		t.Errorf("published keys = %v, want only the kept report", got)
	}
}

// TestEndpointContractsOverWiredHandler checks the HTTP status-code contract on
// the fully assembled handler (ingest + admin sharing one store), over a real
// loopback socket. The exhaustive per-branch cases live in the ingest/handler/
// admin unit tests; this asserts the contract still holds once everything is
// wired together and driven by a real net/http client.
func TestEndpointContractsOverWiredHandler(t *testing.T) {
	p := newPipeline(t)

	// Seed one pending report so the admin cases have a real target id.
	if res := p.ingest(t, reportWithPII(t)); res.status != http.StatusAccepted {
		t.Fatalf("seed ingest = %d, want 202", res.status)
	}
	id := p.pendingIDs(t)[0]

	t.Run("ingest", func(t *testing.T) {
		cases := []struct {
			name        string
			method      string
			contentType string
			body        []byte
			want        int
		}{
			{"valid", http.MethodPost, "application/json", reportWithPII(t), http.StatusAccepted},
			{"malformed json", http.MethodPost, "application/json", []byte(`{"appVersion":`), http.StatusBadRequest},
			{"schema invalid", http.MethodPost, "application/json", []byte(`{"appVersion":"1.0.0","platform":"android"}`), http.StatusBadRequest},
			{"wrong content-type", http.MethodPost, "text/plain", reportWithPII(t), http.StatusUnsupportedMediaType},
			{"wrong method", http.MethodGet, "", nil, http.StatusMethodNotAllowed},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				res := p.do(t, tc.method, "/v1/reports", tc.contentType, "", tc.body)
				if res.status != tc.want {
					t.Errorf("status = %d, want %d (body=%q)", res.status, tc.want, res.raw)
				}
				if tc.name == "wrong method" && res.header.Get("Allow") != http.MethodPost {
					t.Errorf("Allow = %q, want POST", res.header.Get("Allow"))
				}
			})
		}
	})

	t.Run("admin", func(t *testing.T) {
		cases := []struct {
			name   string
			method string
			path   string
			bearer string
			want   int
		}{
			{"list no token", http.MethodGet, "/v1/admin/reports", "", http.StatusUnauthorized},
			{"list bad token", http.MethodGet, "/v1/admin/reports", "wrong", http.StatusUnauthorized},
			{"list authed", http.MethodGet, "/v1/admin/reports", adminToken, http.StatusOK},
			{"remove unknown", http.MethodPost, "/v1/admin/reports/ghost/remove", adminToken, http.StatusNotFound},
			{"wrong method on list", http.MethodPut, "/v1/admin/reports", adminToken, http.StatusMethodNotAllowed},
			{"remove authed", http.MethodPost, "/v1/admin/reports/" + id + "/remove", adminToken, http.StatusOK},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				res := p.do(t, tc.method, tc.path, "", tc.bearer, nil)
				if res.status != tc.want {
					t.Errorf("status = %d, want %d (body=%q)", res.status, tc.want, res.raw)
				}
			})
		}
	})
}
