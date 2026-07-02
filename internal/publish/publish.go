package publish

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/crypto"
)

// DefaultMaxPerRun is ADR #6 §3.1's per-run issue cap: at most 50 issues per
// weekly run. If more reports are pending, the oldest 50 are published and the
// rest stay pending for the next run (schedule/lifecycle list oldest-first).
const DefaultMaxPerRun = 50

// PendingGetter fetches a pending report's still-encrypted frame by id. It is the
// read half of lifecycle.Manager (#10) that the publish job needs; a narrow
// interface keeps this package host-testable and free of the Wasm-only storage
// backends. *lifecycle.Manager satisfies it via GetPending.
type PendingGetter interface {
	GetPending(ctx context.Context, id string) ([]byte, error)
}

// issueCreator is the slice of the GitHub client the Publisher depends on. *Client
// satisfies it; tests use a mock to exercise orchestration (cap, isolation, the
// onPublished seam) without an httptest server.
type issueCreator interface {
	EnsureLabels(ctx context.Context, labels []Label) error
	CreateIssue(ctx context.Context, title, body string, labels []string) (CreatedIssue, error)
}

// Publisher implements schedule.Publisher (#13): given a batch of pending report
// ids it decrypts, formats, and creates one labeled GitHub issue per report,
// isolating per-report failures. It is the real publisher that replaces
// schedule.LogPublisher in the Worker.
type Publisher struct {
	gh          issueCreator
	keyring     *crypto.Keyring
	getter      PendingGetter
	labels      []Label
	maxPerRun   int
	onPublished func(ctx context.Context, id string) error
	logf        func(format string, args ...any)
}

// Option customises a Publisher.
type Option func(*Publisher)

// WithOnPublished sets the post-publish hook. It is invoked once per report,
// immediately after that report's issue is confirmed created (a 201), with the
// report id. This is the seam #15 wires to lifecycle.MarkPublished to complete
// cross-run de-duplication (see the Publish doc). The default is a no-op.
func WithOnPublished(fn func(ctx context.Context, id string) error) Option {
	return func(p *Publisher) {
		if fn != nil {
			p.onPublished = fn
		}
	}
}

// WithMaxPerRun overrides the per-run issue cap (default DefaultMaxPerRun). A
// value ≤ 0 disables the cap.
func WithMaxPerRun(n int) Option {
	return func(p *Publisher) { p.maxPerRun = n }
}

// WithLabels overrides the labels applied to every issue (default DefaultLabels).
func WithLabels(labels []Label) Option {
	return func(p *Publisher) { p.labels = labels }
}

// WithLogger overrides the logger (default log.Printf). Ids are opaque handles
// and safe to log; report plaintext and the GitHub token must never be logged.
func WithLogger(fn func(format string, args ...any)) Option {
	return func(p *Publisher) {
		if fn != nil {
			p.logf = fn
		}
	}
}

// New returns a Publisher that decrypts with kr, reads pending frames from getter,
// and creates issues via gh. kr and getter must be non-nil.
func New(gh *Client, kr *crypto.Keyring, getter PendingGetter, opts ...Option) *Publisher {
	return newPublisher(gh, kr, getter, opts...)
}

// newPublisher is New over the issueCreator seam, so tests can inject a mock
// client. Exported New takes the concrete *Client the Worker constructs.
func newPublisher(gh issueCreator, kr *crypto.Keyring, getter PendingGetter, opts ...Option) *Publisher {
	p := &Publisher{
		gh:          gh,
		keyring:     kr,
		getter:      getter,
		labels:      DefaultLabels,
		maxPerRun:   DefaultMaxPerRun,
		onPublished: func(context.Context, string) error { return nil },
		logf:        log.Printf,
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Publish is the schedule.Publisher entry point. For each pending id (oldest
// first, capped at maxPerRun) it runs GetPending → crypto.Open → format →
// CreateIssue, applying the ADR #6 labels, then calls the onPublished hook.
//
// # De-duplication seam (#15)
//
// This ticket (#14) creates the issues; it deliberately does NOT mark reports
// published. Cross-run de-dup is completed by #15, which injects onPublished →
// lifecycle.MarkPublished so a published report leaves the pending set and is not
// re-published next run. The contract that makes this safe (ADR #6 §3.2,
// "mark published only on a confirmed 201") is upheld here: onPublished runs only
// after CreateIssue returns success, so #15 only ever marks confirmed-created
// reports. Until #15 lands the default onPublished is a no-op, so reports remain
// pending and would republish — acceptable pre-#15 and intentional.
//
// # Failure isolation
//
// A per-report failure (fetch, decrypt, create-after-retries, or onPublished) is
// logged and collected but never aborts the batch: the remaining reports are
// still attempted. Publish returns the joined per-report errors (nil if all
// succeeded), which the Worker surfaces so the scheduled invocation is recorded
// as failed and the maintainer is alerted. A failed report is not marked
// published (onPublished not called), so it is retried on a later run.
func (p *Publisher) Publish(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	batch := ids
	capHit := false
	if p.maxPerRun > 0 && len(batch) > p.maxPerRun {
		batch = batch[:p.maxPerRun] // oldest-first; remainder drains next run
		capHit = true
	}

	// Ensure the three ADR #6 labels exist once per run (idempotent). Best-effort:
	// a failure is surfaced but does not abort publishing — issue creation still
	// references the label names, and any missing label is retried next run.
	var errs []error
	if err := p.gh.EnsureLabels(ctx, p.labels); err != nil {
		p.logf("publish: ensure labels (continuing, labels applied best-effort): %v", err)
		errs = append(errs, fmt.Errorf("ensure labels: %w", err))
	}

	names := LabelNames(p.labels)
	published := 0
	for _, id := range batch {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		if err := p.publishOne(ctx, id, names); err != nil {
			p.logf("publish: report %s failed, left pending: %v", id, err)
			errs = append(errs, fmt.Errorf("report %s: %w", id, err))
			continue
		}
		published++
	}

	if capHit {
		// ADR #6 §3.1: alert the maintainer that the cap was hit and reports were
		// deferred. The log line is the alert channel until dedicated alerting lands.
		p.logf("publish: per-run cap %d reached: published %d of %d pending this run; %d deferred to next run",
			p.maxPerRun, published, len(ids), len(ids)-len(batch))
	}
	p.logf("publish: run complete: %d published, %d failed, of %d attempted",
		published, len(batch)-published, len(batch))

	return errors.Join(errs...)
}

// publishOne runs the full pipeline for a single report id. It returns an error
// (never panics) so the caller can isolate this report from the rest of the batch.
func (p *Publisher) publishOne(ctx context.Context, id string, labelNames []string) error {
	frame, err := p.getter.GetPending(ctx, id)
	if err != nil {
		return fmt.Errorf("get pending: %w", err)
	}
	plaintext, err := crypto.Open(p.keyring, frame)
	if err != nil {
		// A decrypt failure is a hard failure for this report (ADR #5): never fall
		// back to publishing ciphertext. Isolated and surfaced, not fatal.
		return fmt.Errorf("decrypt: %w", err)
	}

	title, body := formatIssue(id, plaintext)
	issue, err := p.gh.CreateIssue(ctx, title, body, labelNames)
	if err != nil {
		return fmt.Errorf("create issue: %w", err)
	}

	// Confirmed 201 Created: invoke the mark-published seam (#15). If it fails the
	// issue still exists; #15 owns reconciling that (its published marker prevents
	// a duplicate next run), so we surface it as this report's error.
	if err := p.onPublished(ctx, id); err != nil {
		return fmt.Errorf("on-published hook (issue %s created): %w", issue.HTMLURL, err)
	}
	p.logf("publish: report %s -> %s", id, issue.HTMLURL)
	return nil
}

// ParseRepo splits an "owner/repo" target string into its parts. It backs the
// configurable target repo (the GITHUB_REPO Worker var); a malformed value is
// rejected with an error rather than silently targeting the wrong repo.
func ParseRepo(s string) (owner, repo string, err error) {
	owner, repo, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
		return "", "", fmt.Errorf("publish: invalid target repo %q, want \"owner/repo\"", s)
	}
	return owner, repo, nil
}

// Compile-time check that the concrete client satisfies the internal seam the
// Publisher depends on.
var _ issueCreator = (*Client)(nil)
