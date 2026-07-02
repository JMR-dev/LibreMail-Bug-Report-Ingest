// Package publish turns pending, encrypted bug-reports into GitHub issues on the
// LibreMail app repo — the "publish" half of the weekly job (#14). It is handed a
// batch of pending report ids by internal/schedule (the Friday-17:00-Central
// gate, #13) and, for each id, fetches the still-encrypted frame
// (lifecycle.GetPending, #10), decrypts it (internal/crypto, #5), formats it into
// a well-formed issue body, and creates a labeled issue via the GitHub REST API.
//
// # Host-testable, Wasm-deployable
//
// The package carries no build constraints. The GitHub client is built on the
// standard net/http (the #26 patch makes net/http's client work under TinyGo's
// js/wasm target, routing through the Cloudflare fetch runtime), so the exact
// same code is exercised by `go test` on the host against an httptest mock and
// runs in the deployed Worker. All wall-clock behaviour (rate-limit spacing,
// backoff sleeps, the ratelimit-reset clock) is injected, so the retry policy is
// unit-tested deterministically with no real sleeps.
//
// # GitHub limits (ADR #6, docs/decisions/labels-and-abuse.md)
//
// The client encodes ADR #6 §3.2 exactly: serial mutations spaced by ≥1s, honour
// Retry-After, wait until x-ratelimit-reset when remaining is 0, a ≥60s floor for
// secondary-rate-limit 403s, and full-jittered exponential backoff (base 1s, cap
// 60s, ≤5 attempts) on 5xx/network errors. Issues carry the three ADR #6 labels
// (bug-report, automated, needs-triage), created if missing. The publish job
// applies the ADR #6 §3.1 per-run cap (50) and the 65,536-char body cap.
package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GitHub API defaults.
const (
	// defaultBaseURL is the public GitHub REST API root. Overridable with
	// WithBaseURL so tests can point the client at an httptest server.
	defaultBaseURL = "https://api.github.com"
	// apiVersion is sent as X-GitHub-Api-Version, pinning the REST API contract.
	apiVersion = "2022-11-28"
	// userAgent identifies this job to GitHub (a User-Agent header is required).
	userAgent = "LibreMail-Bug-Report-Ingest"
)

// Retry/pacing defaults, from ADR #6 §3.2.
const (
	// defaultMinSpacing is the minimum wall-clock gap between mutating requests
	// (issue/label creation). ADR #6: "space successful creates by ≥1 second".
	defaultMinSpacing = 1 * time.Second
	// defaultBaseBackoff and defaultCapBackoff bound the exponential schedule
	// min(60s, 1s·2^attempt).
	defaultBaseBackoff = 1 * time.Second
	defaultCapBackoff  = 60 * time.Second
	// defaultSecondaryMin is the ≥60s floor for a secondary-rate-limit 403 that
	// arrives without a Retry-After header.
	defaultSecondaryMin = 60 * time.Second
	// defaultMaxAttempts is the per-request attempt cap (ADR #6: "max 5 attempts
	// per issue"): the initial try plus up to four backoff retries.
	defaultMaxAttempts = 5
)

// Client is a minimal GitHub REST API client scoped to one owner/repo. It creates
// labels and issues and applies ADR #6's pacing, backoff, and rate-limit policy.
// It is safe for the serial, single-goroutine use the scheduled publish job makes
// of it; it does not add its own concurrency.
type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
	owner      string
	repo       string

	minSpacing   time.Duration
	baseBackoff  time.Duration
	capBackoff   time.Duration
	secondaryMin time.Duration
	maxAttempts  int

	// Injected wall-clock + randomness seams, so backoff/spacing are deterministic
	// and instant under test. Defaults use real time and math/rand.
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
	randf func() float64

	mu           sync.Mutex
	lastMutation time.Time // time of the last mutating request (for spacing)
}

// ClientOption customises a Client. The wall-clock/rand options exist for tests.
type ClientOption func(*Client)

// WithBaseURL overrides the GitHub API root (tests point it at httptest).
func WithBaseURL(u string) ClientOption {
	return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") }
}

// WithHTTPClient overrides the underlying *http.Client.
func WithHTTPClient(h *http.Client) ClientOption {
	return func(c *Client) { c.httpClient = h }
}

// WithClock injects the time source and sleep function (tests use a virtual
// clock so backoff/spacing incur no real delay). Both must be set together.
func WithClock(now func() time.Time, sleep func(context.Context, time.Duration) error) ClientOption {
	return func(c *Client) {
		if now != nil {
			c.now = now
		}
		if sleep != nil {
			c.sleep = sleep
		}
	}
}

// WithRand injects the [0,1) source used for full-jitter backoff (tests pin it
// to make jittered sleeps deterministic).
func WithRand(randf func() float64) ClientOption {
	return func(c *Client) {
		if randf != nil {
			c.randf = randf
		}
	}
}

// WithMaxAttempts overrides the per-request attempt cap (default 5).
func WithMaxAttempts(n int) ClientOption {
	return func(c *Client) {
		if n > 0 {
			c.maxAttempts = n
		}
	}
}

// WithSpacing overrides the minimum gap between mutating requests (default 1s).
func WithSpacing(d time.Duration) ClientOption {
	return func(c *Client) { c.minSpacing = d }
}

// NewClient returns a Client for github.com/<owner>/<repo> authenticated with
// token (a Worker secret; never log it). Defaults encode ADR #6 §3.2; override
// via options (mainly in tests).
func NewClient(token, owner, repo string, opts ...ClientOption) *Client {
	src := rand.New(rand.NewSource(time.Now().UnixNano())) // jitter only; not crypto
	c := &Client{
		httpClient:   &http.Client{},
		baseURL:      defaultBaseURL,
		token:        token,
		owner:        owner,
		repo:         repo,
		minSpacing:   defaultMinSpacing,
		baseBackoff:  defaultBaseBackoff,
		capBackoff:   defaultCapBackoff,
		secondaryMin: defaultSecondaryMin,
		maxAttempts:  defaultMaxAttempts,
		now:          time.Now,
		sleep:        sleepCtx,
		randf:        src.Float64,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// sleepCtx sleeps for d, returning early if ctx is cancelled. It is the default
// Client sleep; tests swap in a virtual-clock sleep that returns instantly.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Label is a GitHub issue label to ensure-exists and apply. Colour is a 6-hex-
// digit string without the leading '#'.
type Label struct {
	Name        string
	Color       string
	Description string
}

// DefaultLabels are the three ADR #6 §1 labels every auto-published issue carries.
// Names are the binding contract; colours are advisory (the maintainer may
// recolour). All three are applied at issue creation.
var DefaultLabels = []Label{
	{Name: "bug-report", Color: "e99695", Description: "Originated from the app's opt-in debug bug-report ingest pipeline."},
	{Name: "automated", Color: "c5def5", Description: "Created by the weekly publish job, not written by a human."},
	{Name: "needs-triage", Color: "fbca04", Description: "Not yet reviewed or confirmed by the maintainer."},
}

// LabelNames returns just the label names, for the issue-creation payload.
func LabelNames(labels []Label) []string {
	names := make([]string, len(labels))
	for i, l := range labels {
		names[i] = l.Name
	}
	return names
}

// CreatedIssue is the slice of GitHub's issue-creation response the job needs.
type CreatedIssue struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
}

// EnsureLabels creates each label that does not yet exist, idempotently (ADR #6:
// "create-or-ignore"). An already-existing label (HTTP 422) is treated as
// success. Errors for individual labels are joined; callers may treat a failure
// as best-effort (issue creation still references the label names).
func (c *Client) EnsureLabels(ctx context.Context, labels []Label) error {
	var errs []error
	for _, l := range labels {
		if err := c.ensureLabel(ctx, l); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// labelRequest / issueRequest are the JSON bodies for the two POST endpoints.
type labelRequest struct {
	Name        string `json:"name"`
	Color       string `json:"color"`
	Description string `json:"description,omitempty"`
}

type issueRequest struct {
	Title  string   `json:"title"`
	Body   string   `json:"body"`
	Labels []string `json:"labels,omitempty"`
}

func (c *Client) ensureLabel(ctx context.Context, l Label) error {
	body, err := json.Marshal(labelRequest{Name: l.Name, Color: l.Color, Description: l.Description})
	if err != nil {
		return fmt.Errorf("github: marshal label %q: %w", l.Name, err)
	}
	status, respBody, err := c.do(ctx, http.MethodPost, c.repoPath("labels"), body)
	if err != nil {
		return fmt.Errorf("github: create label %q: %w", l.Name, err)
	}
	switch status {
	case http.StatusCreated:
		return nil
	case http.StatusUnprocessableEntity:
		// 422 on label creation means the name already exists ("already_exists"):
		// the idempotent create-or-ignore outcome ADR #6 asks for.
		return nil
	default:
		return fmt.Errorf("github: create label %q: unexpected status %d: %s", l.Name, status, snippet(respBody))
	}
}

// CreateIssue creates one issue and returns it. Per ADR #6 a report is publishable
// only on a confirmed 201 Created, so a nil error from CreateIssue is exactly that
// confirmation — the caller marks the report published only then.
func (c *Client) CreateIssue(ctx context.Context, title, body string, labels []string) (CreatedIssue, error) {
	reqBody, err := json.Marshal(issueRequest{Title: title, Body: body, Labels: labels})
	if err != nil {
		return CreatedIssue{}, fmt.Errorf("github: marshal issue: %w", err)
	}
	status, respBody, err := c.do(ctx, http.MethodPost, c.repoPath("issues"), reqBody)
	if err != nil {
		return CreatedIssue{}, fmt.Errorf("github: create issue: %w", err)
	}
	if status != http.StatusCreated {
		return CreatedIssue{}, fmt.Errorf("github: create issue: unexpected status %d: %s", status, snippet(respBody))
	}
	var issue CreatedIssue
	if err := json.Unmarshal(respBody, &issue); err != nil {
		return CreatedIssue{}, fmt.Errorf("github: create issue: decode response: %w", err)
	}
	return issue, nil
}

// repoPath builds "/repos/<owner>/<repo>/<sub>".
func (c *Client) repoPath(sub string) string {
	return "/repos/" + c.owner + "/" + c.repo + "/" + sub
}

// do performs a mutating request with ADR #6 pacing + retry. It returns the final
// HTTP status and body. A non-nil error means the request could not be completed
// within the attempt budget (a transport error, or an exhausted-retry status); a
// non-retryable HTTP status (2xx, or a 4xx like 401/404/422) returns that status
// with a nil error so the caller can interpret it.
func (c *Client) do(ctx context.Context, method, path string, reqBody []byte) (int, []byte, error) {
	url := c.baseURL + path
	var (
		lastStatus int
		lastBody   []byte
		lastErr    error
	)
	for attempt := 0; attempt < c.maxAttempts; attempt++ {
		// Serialize + space mutations (ADR #6): ensure ≥minSpacing since the last
		// one before issuing this attempt.
		if err := c.spaceMutations(ctx); err != nil {
			return 0, nil, err
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(reqBody))
		if err != nil {
			return 0, nil, err // request construction failure is not retryable
		}
		c.setHeaders(req)

		resp, err := c.httpClient.Do(req)
		c.recordMutation()

		var wait time.Duration
		var retryable bool
		if err != nil {
			// Network/transport error: retry with jittered exponential backoff.
			lastStatus, lastBody, lastErr = 0, nil, err
			wait, retryable = c.jitteredBackoff(attempt), true
		} else {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				lastStatus, lastBody, lastErr = 0, nil, readErr
				wait, retryable = c.jitteredBackoff(attempt), true
			} else {
				wait, retryable = c.retryDecision(resp, body, attempt)
				if !retryable {
					return resp.StatusCode, body, nil
				}
				lastStatus, lastBody = resp.StatusCode, body
				lastErr = fmt.Errorf("status %d: %s", resp.StatusCode, snippet(body))
			}
		}

		if attempt == c.maxAttempts-1 {
			return lastStatus, lastBody, fmt.Errorf("github: %s %s: gave up after %d attempt(s): %w",
				method, path, c.maxAttempts, lastErr)
		}
		if err := c.sleep(ctx, wait); err != nil {
			return 0, nil, err
		}
	}
	// Unreachable (maxAttempts ≥ 1), but keeps the compiler happy.
	return lastStatus, lastBody, lastErr
}

// setHeaders applies the standard GitHub REST headers. The token is a secret and
// must never be logged.
func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
}

// retryDecision encodes ADR #6 §3.2's rate-limit/error policy: it reports how long
// to wait before the next attempt and whether the response is retryable at all.
//
//   - 5xx: retryable, jittered exponential backoff.
//   - 403/429 with Retry-After: retryable, honour it exactly.
//   - 403/429 with x-ratelimit-remaining: 0: retryable, wait until x-ratelimit-reset.
//   - 429 otherwise: retryable, jittered exponential backoff.
//   - 403 secondary rate limit without Retry-After: retryable, ≥60s then exponential.
//   - 403 without any rate-limit signal (a permission error): NOT retryable.
//   - everything else (2xx/4xx): not retryable (the caller interprets the status).
func (c *Client) retryDecision(resp *http.Response, body []byte, attempt int) (time.Duration, bool) {
	code := resp.StatusCode
	if code >= 500 {
		return c.jitteredBackoff(attempt), true
	}
	if code != http.StatusForbidden && code != http.StatusTooManyRequests {
		return 0, false
	}

	if d, ok := parseRetryAfter(resp.Header.Get("Retry-After")); ok {
		return d, true // honour Retry-After exactly (overrides computed backoff)
	}
	if resp.Header.Get("X-RateLimit-Remaining") == "0" {
		if d, ok := c.untilReset(resp.Header.Get("X-RateLimit-Reset")); ok {
			return d, true
		}
		return c.jitteredBackoff(attempt), true // remaining=0 but no usable reset
	}
	if code == http.StatusTooManyRequests {
		return c.jitteredBackoff(attempt), true
	}
	// From here code == 403 with no Retry-After and remaining != 0.
	if isSecondaryRateLimit(body) {
		d := c.jitteredBackoff(attempt)
		if d < c.secondaryMin {
			d = c.secondaryMin // ADR #6: ≥60s floor for secondary limit
		}
		return d, true
	}
	// A plain 403 (bad token, no push access, ...) is permanent — do not retry.
	return 0, false
}

// spaceMutations blocks until at least minSpacing has elapsed since the previous
// mutating request, implementing ADR #6's "≥1s between mutations".
func (c *Client) spaceMutations(ctx context.Context) error {
	c.mu.Lock()
	last := c.lastMutation
	c.mu.Unlock()
	if last.IsZero() {
		return nil
	}
	if elapsed := c.now().Sub(last); elapsed < c.minSpacing {
		return c.sleep(ctx, c.minSpacing-elapsed)
	}
	return nil
}

// recordMutation stamps the time of the just-issued mutating request.
func (c *Client) recordMutation() {
	c.mu.Lock()
	c.lastMutation = c.now()
	c.mu.Unlock()
}

// jitteredBackoff returns a full-jitter delay in [0, min(cap, base·2^attempt)]
// (ADR #6: base 1s, cap 60s, full jitter).
func (c *Client) jitteredBackoff(attempt int) time.Duration {
	backoff := c.baseBackoff << attempt // base · 2^attempt
	if backoff <= 0 || backoff > c.capBackoff {
		backoff = c.capBackoff
	}
	return time.Duration(c.randf() * float64(backoff))
}

// untilReset parses an x-ratelimit-reset epoch-seconds header and returns the
// (clamped, +1s buffer) wait until that instant per the injected clock.
func (c *Client) untilReset(reset string) (time.Duration, bool) {
	if reset == "" {
		return 0, false
	}
	epoch, err := strconv.ParseInt(strings.TrimSpace(reset), 10, 64)
	if err != nil {
		return 0, false
	}
	d := time.Unix(epoch, 0).Sub(c.now())
	if d < 0 {
		d = 0
	}
	return d + time.Second, true // small buffer so we wake just after reset
}

// parseRetryAfter parses a Retry-After header expressed as integer seconds (the
// form GitHub sends). Returns false if absent or unparseable.
func parseRetryAfter(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs < 0 {
		return 0, false
	}
	return time.Duration(secs) * time.Second, true
}

// isSecondaryRateLimit reports whether a 403 body is GitHub's secondary-rate-limit
// message (as opposed to a permission error), so only the former is retried.
func isSecondaryRateLimit(body []byte) bool {
	lower := bytes.ToLower(body)
	return bytes.Contains(lower, []byte("secondary rate limit")) ||
		bytes.Contains(lower, []byte("abuse detection"))
}

// snippet returns a short, single-line excerpt of a response body for error
// messages (bounded so a huge body cannot bloat a log line).
func snippet(body []byte) string {
	const max = 200
	s := strings.TrimSpace(string(body))
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
