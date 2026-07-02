package publish

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- test doubles: a virtual clock and a scriptable GitHub API mock ---

// fakeClock is a virtual clock whose time only advances when Sleep is called, so
// backoff/spacing are exercised with zero real delay and are assertable.
type fakeClock struct {
	mu     sync.Mutex
	t      time.Time
	sleeps []time.Duration
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
}

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
		f.sleeps = append(f.sleeps, d)
	}
	return nil
}

func (f *fakeClock) sleepCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sleeps)
}

func (f *fakeClock) lastSleep() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sleeps) == 0 {
		return 0
	}
	return f.sleeps[len(f.sleeps)-1]
}

// scriptedResp is one canned HTTP response for the mock.
type scriptedResp struct {
	status int
	header map[string]string
	body   string
}

// ghServer is a scriptable mock of the GitHub REST API for POST /labels and
// POST /issues. issueScript/labelScript are consumed front-to-back; when empty a
// default 201 is returned (and, for issues, a synthetic created-issue body).
type ghServer struct {
	mu            sync.Mutex
	labelReqs     []labelRequest
	createdIssues []issueRequest // recorded only on a 201 response
	issueAttempts int
	labelAttempts int
	issueScript   []scriptedResp
	labelScript   []scriptedResp
	nextIssueNum  int
	authHeaders   []string
	uaHeaders     []string
	apiVersions   []string
}

func (g *ghServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.authHeaders = append(g.authHeaders, r.Header.Get("Authorization"))
	g.uaHeaders = append(g.uaHeaders, r.Header.Get("User-Agent"))
	g.apiVersions = append(g.apiVersions, r.Header.Get("X-GitHub-Api-Version"))

	switch {
	case strings.HasSuffix(r.URL.Path, "/labels") && r.Method == http.MethodPost:
		var lr labelRequest
		_ = json.NewDecoder(r.Body).Decode(&lr)
		g.labelReqs = append(g.labelReqs, lr)
		g.labelAttempts++
		resp := popScript(&g.labelScript, scriptedResp{status: http.StatusCreated, body: `{}`})
		writeResp(w, resp)

	case strings.HasSuffix(r.URL.Path, "/issues") && r.Method == http.MethodPost:
		var ir issueRequest
		_ = json.NewDecoder(r.Body).Decode(&ir)
		g.issueAttempts++
		resp := popScript(&g.issueScript, scriptedResp{})
		if resp.status == 0 { // default: synthesize a success
			g.nextIssueNum++
			n := g.nextIssueNum
			resp = scriptedResp{
				status: http.StatusCreated,
				body:   fmt.Sprintf(`{"number":%d,"html_url":"https://github.com/o/r/issues/%d"}`, n, n),
			}
		}
		if resp.status == http.StatusCreated {
			g.createdIssues = append(g.createdIssues, ir)
		}
		writeResp(w, resp)

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func popScript(q *[]scriptedResp, def scriptedResp) scriptedResp {
	if len(*q) == 0 {
		return def
	}
	r := (*q)[0]
	*q = (*q)[1:]
	return r
}

func writeResp(w http.ResponseWriter, r scriptedResp) {
	for k, v := range r.header {
		w.Header().Set(k, v)
	}
	w.WriteHeader(r.status)
	_, _ = w.Write([]byte(r.body))
}

// testClient builds a Client aimed at srvURL with a virtual clock and max-jitter
// (randf==1) so exponential backoff is the full computed value, deterministically.
func testClient(srvURL string, fc *fakeClock, opts ...ClientOption) *Client {
	base := []ClientOption{
		WithBaseURL(srvURL),
		WithClock(fc.now, fc.sleep),
		WithRand(func() float64 { return 1.0 }),
	}
	return NewClient("test-token", "o", "r", append(base, opts...)...)
}

// --- tests ---

func TestCreateIssueSuccess(t *testing.T) {
	g := &ghServer{}
	srv := httptest.NewServer(g)
	defer srv.Close()
	c := testClient(srv.URL, newFakeClock())

	issue, err := c.CreateIssue(context.Background(), "the title", "the body", []string{"bug-report", "automated"})
	if err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	if issue.Number != 1 || !strings.Contains(issue.HTMLURL, "/issues/1") {
		t.Errorf("unexpected issue: %+v", issue)
	}
	if len(g.createdIssues) != 1 {
		t.Fatalf("server recorded %d issues, want 1", len(g.createdIssues))
	}
	got := g.createdIssues[0]
	if got.Title != "the title" || got.Body != "the body" {
		t.Errorf("issue payload = %+v", got)
	}
	if len(got.Labels) != 2 || got.Labels[0] != "bug-report" {
		t.Errorf("labels = %v", got.Labels)
	}
	// Required GitHub headers.
	if g.authHeaders[0] != "Bearer test-token" {
		t.Errorf("auth header = %q", g.authHeaders[0])
	}
	if g.uaHeaders[0] == "" {
		t.Error("missing User-Agent")
	}
	if g.apiVersions[0] != apiVersion {
		t.Errorf("api version = %q, want %q", g.apiVersions[0], apiVersion)
	}
}

func TestEnsureLabelsCreateOrIgnore(t *testing.T) {
	g := &ghServer{
		// First label already exists (422), the rest are created (201, the default).
		labelScript: []scriptedResp{{status: http.StatusUnprocessableEntity, body: `{"message":"Validation Failed"}`}},
	}
	srv := httptest.NewServer(g)
	defer srv.Close()
	c := testClient(srv.URL, newFakeClock())

	if err := c.EnsureLabels(context.Background(), DefaultLabels); err != nil {
		t.Fatalf("EnsureLabels: %v", err)
	}
	if g.labelAttempts != len(DefaultLabels) {
		t.Fatalf("label POSTs = %d, want %d", g.labelAttempts, len(DefaultLabels))
	}
	// Names and colours must match the ADR contract.
	names := map[string]string{}
	for _, l := range g.labelReqs {
		names[l.Name] = l.Color
	}
	for _, want := range DefaultLabels {
		if names[want.Name] != want.Color {
			t.Errorf("label %q colour = %q, want %q", want.Name, names[want.Name], want.Color)
		}
	}
}

func TestRetryOn5xxThenSucceeds(t *testing.T) {
	fc := newFakeClock()
	g := &ghServer{issueScript: []scriptedResp{{status: http.StatusInternalServerError, body: "boom"}}}
	srv := httptest.NewServer(g)
	defer srv.Close()
	c := testClient(srv.URL, fc)

	if _, err := c.CreateIssue(context.Background(), "t", "b", nil); err != nil {
		t.Fatalf("CreateIssue should recover after a transient 500: %v", err)
	}
	if g.issueAttempts != 2 {
		t.Errorf("issue attempts = %d, want 2 (one 500, one success)", g.issueAttempts)
	}
	// One backoff sleep of the full attempt-0 backoff (1s, randf==1).
	if fc.sleepCount() != 1 || fc.lastSleep() != 1*time.Second {
		t.Errorf("backoff sleeps = %v (count %d), want a single 1s sleep", fc.sleeps, fc.sleepCount())
	}
}

func TestRetryAfterHonoredExactly(t *testing.T) {
	fc := newFakeClock()
	g := &ghServer{issueScript: []scriptedResp{{
		status: http.StatusTooManyRequests,
		header: map[string]string{"Retry-After": "3"},
		body:   "slow down",
	}}}
	srv := httptest.NewServer(g)
	defer srv.Close()
	c := testClient(srv.URL, fc)

	if _, err := c.CreateIssue(context.Background(), "t", "b", nil); err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	// Retry-After overrides computed backoff: exactly 3s, not jittered.
	if fc.lastSleep() != 3*time.Second {
		t.Errorf("waited %v, want exactly 3s (Retry-After honoured)", fc.lastSleep())
	}
}

func TestRateLimitResetHonored(t *testing.T) {
	fc := newFakeClock()
	reset := fc.now().Add(30 * time.Second).Unix()
	g := &ghServer{issueScript: []scriptedResp{{
		status: http.StatusForbidden,
		header: map[string]string{
			"X-RateLimit-Remaining": "0",
			"X-RateLimit-Reset":     fmt.Sprintf("%d", reset),
		},
		body: "rate limited",
	}}}
	srv := httptest.NewServer(g)
	defer srv.Close()
	c := testClient(srv.URL, fc)

	if _, err := c.CreateIssue(context.Background(), "t", "b", nil); err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	// Waits until reset (30s) plus the 1s wake buffer.
	if fc.lastSleep() != 31*time.Second {
		t.Errorf("waited %v, want 31s (until x-ratelimit-reset + 1s)", fc.lastSleep())
	}
}

func TestSecondaryRateLimitFloor(t *testing.T) {
	fc := newFakeClock()
	// A secondary-rate-limit 403 with no Retry-After: floor of 60s applies even
	// though the attempt-0 exponential backoff would be only ~1s.
	g := &ghServer{issueScript: []scriptedResp{{
		status: http.StatusForbidden,
		body:   `{"message":"You have exceeded a secondary rate limit"}`,
	}}}
	srv := httptest.NewServer(g)
	defer srv.Close()
	c := testClient(srv.URL, fc)

	if _, err := c.CreateIssue(context.Background(), "t", "b", nil); err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	if fc.lastSleep() < 60*time.Second {
		t.Errorf("secondary-limit wait = %v, want ≥60s", fc.lastSleep())
	}
}

func TestPermission403NotRetried(t *testing.T) {
	fc := newFakeClock()
	// A plain 403 with no rate-limit signals is a permission error: surface it
	// immediately, do not retry.
	g := &ghServer{issueScript: []scriptedResp{{
		status: http.StatusForbidden,
		body:   `{"message":"Resource not accessible by personal access token"}`,
	}}}
	srv := httptest.NewServer(g)
	defer srv.Close()
	c := testClient(srv.URL, fc)

	_, err := c.CreateIssue(context.Background(), "t", "b", nil)
	if err == nil {
		t.Fatal("expected an error for a permission 403")
	}
	if g.issueAttempts != 1 {
		t.Errorf("issue attempts = %d, want 1 (permission 403 must not retry)", g.issueAttempts)
	}
	if fc.sleepCount() != 0 {
		t.Errorf("slept %d times on a non-retryable 403, want 0", fc.sleepCount())
	}
}

func TestMaxAttemptsExhausted(t *testing.T) {
	fc := newFakeClock()
	// Every attempt fails with 500; with maxAttempts=3 the client gives up after 3.
	g := &ghServer{issueScript: []scriptedResp{
		{status: http.StatusBadGateway, body: "1"},
		{status: http.StatusBadGateway, body: "2"},
		{status: http.StatusBadGateway, body: "3"},
		{status: http.StatusBadGateway, body: "4"},
	}}
	srv := httptest.NewServer(g)
	defer srv.Close()
	c := testClient(srv.URL, fc, WithMaxAttempts(3))

	_, err := c.CreateIssue(context.Background(), "t", "b", nil)
	if err == nil {
		t.Fatal("expected an error after exhausting attempts")
	}
	if g.issueAttempts != 3 {
		t.Errorf("issue attempts = %d, want 3", g.issueAttempts)
	}
	// Two backoffs between three attempts.
	if fc.sleepCount() != 2 {
		t.Errorf("backoff sleeps = %d, want 2", fc.sleepCount())
	}
}

func TestSpacingBetweenMutations(t *testing.T) {
	fc := newFakeClock()
	g := &ghServer{}
	srv := httptest.NewServer(g)
	defer srv.Close()
	c := testClient(srv.URL, fc)

	// Two consecutive creates with no time passing between them: the second must
	// be spaced by ≥1s (ADR #6).
	if _, err := c.CreateIssue(context.Background(), "a", "b", nil); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := c.CreateIssue(context.Background(), "c", "d", nil); err != nil {
		t.Fatalf("second create: %v", err)
	}
	if fc.sleepCount() != 1 || fc.lastSleep() != 1*time.Second {
		t.Errorf("spacing sleeps = %v, want a single 1s spacing before the 2nd create", fc.sleeps)
	}
}
