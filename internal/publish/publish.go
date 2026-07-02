package publish

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/crypto"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/telemetry"
)

// DefaultMaxPerRun is ADR #6 §3.1's per-run issue cap: at most 50 issues per
// weekly run. If more reports are pending, the oldest 50 are published and the
// rest stay pending for the next run (schedule/lifecycle list oldest-first).
const DefaultMaxPerRun = 50

// Alert types (issue #17) emitted as structured OTEL signals so a backend alert
// can key on them once an OTLP endpoint is chosen (TBD).
const (
	// alertCapHit fires when the per-run cap defers reports (the #14 follow-up:
	// this previously only logged; it is now also a structured, alertable signal).
	alertCapHit = "publish.cap_hit"
	// alertRunFailed fires when the run finishes with one or more failures.
	alertRunFailed = "publish.run_failed"
)

// PendingGetter fetches a pending report's still-encrypted frame by id. It is the
// read half of lifecycle.Manager (#10) that the publish job needs; a narrow
// interface keeps this package host-testable and free of the Wasm-only storage
// backends. *lifecycle.Manager satisfies it via GetPending.
type PendingGetter interface {
	GetPending(ctx context.Context, id string) ([]byte, error)
}

// Marker is the write half of lifecycle.Manager (#10) the publish job needs to
// complete cross-run de-duplication (#15): once a report is confirmed published as
// a GitHub issue (a 201), MarkPublished transitions it out of the pending set so a
// later run's ListPending no longer returns it and it is never re-published. It is
// idempotent — re-marking an already-published id succeeds — so a retried mark
// converges. *lifecycle.Manager satisfies it via MarkPublished. A narrow interface
// (mirroring PendingGetter, the read half) keeps this package host-testable and
// free of the Wasm-only storage backends.
type Marker interface {
	MarkPublished(ctx context.Context, id string) error
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

// WithMarkPublished wires the post-publish hook (see WithOnPublished) to m's
// lifecycle transition, completing #15: each report is marked published the moment
// its issue is confirmed created, so it leaves the pending set and the next run's
// ListPending does not return it — no duplicate issue. This is the production
// wiring the Worker's buildPublish uses; host tests use it with a real
// lifecycle.Manager over a MemoryStore.
//
// # The partial-failure guarantee (why de-dup falls out for free)
//
// The hook runs only on a confirmed 201 and per-report failures are isolated (see
// Publish/publishOne). So in a run of N reports where report k fails to create,
// reports that already succeeded were each marked published and drop out of the
// pending set, while k (and any later failure) was never marked and stays pending.
// The next run lists only the still-pending reports and retries exactly those,
// never re-creating the already-published ones.
//
// # Mark-failure risk (honest note)
//
// Because the hook runs after the 201, the issue already exists when MarkPublished
// runs. If MarkPublished then fails, the report stays pending and WILL be
// re-published as a DUPLICATE issue next run — there is no GitHub-side idempotency
// key to prevent that, and we cannot un-create the issue. We surface the failure
// two ways: a loud log line naming the report and the duplicate risk, and the
// returned error (which fails the run so the maintainer is alerted). MarkPublished
// is itself idempotent, so a *partially* applied transition (copy done, delete
// not) converges on any later mark; the residual exposure is at most one duplicate
// issue, flagged loudly for manual reconciliation.
func WithMarkPublished(m Marker) Option {
	return func(p *Publisher) {
		if m == nil {
			return
		}
		p.onPublished = func(ctx context.Context, id string) error {
			if err := m.MarkPublished(ctx, id); err != nil {
				// The issue is already created (this runs only on a confirmed 201). A
				// failed mark leaves the report pending, so it may be re-published as a
				// duplicate next run. Log loudly; the error is also returned to fail the
				// run. p.logf is read at call time, so it reflects any WithLogger override.
				p.logf("publish: WARNING report %s was published as a GitHub issue but MarkPublished failed: %v; "+
					"it remains pending and may be re-published as a DUPLICATE next run "+
					"(MarkPublished is idempotent, so a later retry converges)", id, err)
				return err
			}
			return nil
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
// This package creates the issues; cross-run de-dup is completed by wiring
// onPublished → lifecycle.MarkPublished (WithMarkPublished, #15) so a published
// report leaves the pending set and is not re-published next run. The contract
// that makes this safe (ADR #6 §3.2, "mark published only on a confirmed 201") is
// upheld here: onPublished runs only after CreateIssue returns success, so the
// hook only ever marks confirmed-created reports. Left at its default no-op (no
// WithMarkPublished), reports remain pending and would republish next run.
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
	// Observability (#17): a run-level span plus per-report child spans and a
	// correlated log per report. When no telemetry provider rides in ctx (the
	// default until an OTLP endpoint is configured) every call here is a no-op and
	// behaviour is unchanged. The span is a child of the schedule.run span when
	// invoked from the weekly trigger.
	tel := telemetry.FromContext(ctx)
	ctx, span := tel.StartSpan(ctx, "publish.run", telemetry.WithSpanKind(telemetry.SpanKindInternal))
	defer span.End()
	span.SetAttributes(telemetry.Int("publish.pending", len(ids)))

	if len(ids) == 0 {
		span.SetAttributes(telemetry.Int("publish.attempted", 0), telemetry.Int("publish.published", 0))
		span.SetStatus(telemetry.StatusOK, "")
		tel.Info(ctx, "publish run: no pending reports")
		return nil
	}

	batch := ids
	capHit := false
	if p.maxPerRun > 0 && len(batch) > p.maxPerRun {
		batch = batch[:p.maxPerRun] // oldest-first; remainder drains next run
		capHit = true
	}
	span.SetAttributes(telemetry.Int("publish.attempted", len(batch)))

	// Ensure the three ADR #6 labels exist once per run (idempotent). Best-effort:
	// a failure is surfaced but does not abort publishing — issue creation still
	// references the label names, and any missing label is retried next run.
	var errs []error
	if err := p.gh.EnsureLabels(ctx, p.labels); err != nil {
		p.logf("publish: ensure labels (continuing, labels applied best-effort): %v", err)
		errs = append(errs, fmt.Errorf("ensure labels: %w", err))
		tel.Warn(ctx, "publish: ensure labels failed (continuing best-effort)",
			telemetry.String("error", err.Error()))
	}

	names := LabelNames(p.labels)
	published := 0
	for _, id := range batch {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		rctx, rspan := tel.StartSpan(ctx, "publish.report",
			telemetry.WithSpanKind(telemetry.SpanKindInternal),
			telemetry.WithAttributes(telemetry.String("report.id", id)))
		if err := p.publishOne(rctx, id, names); err != nil {
			p.logf("publish: report %s failed, left pending: %v", id, err)
			errs = append(errs, fmt.Errorf("report %s: %w", id, err))
			rspan.SetAttributes(telemetry.String("report.outcome", "failed"))
			rspan.SetStatus(telemetry.StatusError, err.Error())
			tel.Error(rctx, "publish: report failed, left pending",
				telemetry.String("report.id", id),
				telemetry.String("report.outcome", "failed"),
				telemetry.String("error", err.Error()))
			rspan.End()
			continue
		}
		published++
		rspan.SetAttributes(telemetry.String("report.outcome", "published"))
		rspan.SetStatus(telemetry.StatusOK, "")
		tel.Info(rctx, "publish: report published",
			telemetry.String("report.id", id),
			telemetry.String("report.outcome", "published"))
		rspan.End()
	}

	if capHit {
		deferred := len(ids) - len(batch)
		// ADR #6 §3.1: alert the maintainer that the cap was hit and reports were
		// deferred. The log line remains for humans...
		p.logf("publish: per-run cap %d reached: published %d of %d pending this run; %d deferred to next run",
			p.maxPerRun, published, len(ids), deferred)
		// ...and (#17, folding in the #14 follow-up) the cap-hit is now also emitted
		// as a structured, alertable OTEL signal rather than only a log line.
		span.AddEvent(alertCapHit,
			telemetry.Int("publish.cap", p.maxPerRun),
			telemetry.Int("publish.deferred", deferred))
		span.SetAttributes(telemetry.Bool("publish.cap_hit", true), telemetry.Int("publish.deferred", deferred))
		capAttrs := append(telemetry.Alert(alertCapHit),
			telemetry.Int("publish.cap", p.maxPerRun),
			telemetry.Int("publish.published", published),
			telemetry.Int("publish.pending", len(ids)),
			telemetry.Int("publish.deferred", deferred))
		tel.Warn(ctx, "publish: per-run cap reached; reports deferred to next run", capAttrs...)
	}
	p.logf("publish: run complete: %d published, %d failed, of %d attempted",
		published, len(batch)-published, len(batch))

	joined := errors.Join(errs...)
	failed := len(batch) - published
	span.SetAttributes(
		telemetry.Int("publish.published", published),
		telemetry.Int("publish.failed", failed),
	)
	if joined != nil {
		span.SetStatus(telemetry.StatusError, joined.Error())
		runAttrs := append(telemetry.Alert(alertRunFailed),
			telemetry.Int("publish.published", published),
			telemetry.Int("publish.failed", failed),
			telemetry.Int("publish.attempted", len(batch)))
		tel.Error(ctx, "publish run failed", runAttrs...)
	} else {
		span.SetStatus(telemetry.StatusOK, "")
		tel.Info(ctx, "publish run complete",
			telemetry.Int("publish.published", published),
			telemetry.Int("publish.failed", failed))
	}
	return joined
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
