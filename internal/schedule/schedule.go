// Package schedule holds the timezone gate and orchestration for the weekly
// publish trigger (#13): "every Friday at 17:00 America/Chicago (Central), list
// the pending reports and hand them to the publish step".
//
// # Why a gate is needed at all
//
// Cloudflare Cron Triggers are evaluated in UTC and have no timezone support, so
// a single UTC cron cannot express "17:00 America/Chicago" year-round: Central is
// UTC-5 during Daylight time (CDT, summer) and UTC-6 during Standard time (CST,
// winter), so 17:00 Central is 22:00 UTC for part of the year and 23:00 UTC for
// the rest. The Worker therefore registers BOTH candidate Friday UTC hours in
// wrangler.jsonc (`0 22 * * 5` and `0 23 * * 5`) and gates each fire with
// [IsFriday1700Central]: exactly one of the two fires is 17:00 Central on any
// given Friday, so [Run] does the publish work exactly once per week across the
// CST/CDT boundary and does nothing on the other fire.
//
// # No timezone database needed
//
// The gate deliberately does not call time.LoadLocation("America/Chicago"): the
// Worker is compiled to Wasm by TinyGo, whose runtime may not embed the IANA
// tz database, so a LoadLocation could fail at deploy time. Instead the US
// Central DST rule is computed from first principles (see centralIsDaylight):
// Daylight time runs from the 2nd Sunday of March at 02:00 to the 1st Sunday of
// November at 02:00. This keeps the decision a pure function of a time.Time with
// no external data, so it is host-testable exhaustively without TinyGo (and the
// tests cross-check it against the real IANA zone via time/tzdata).
package schedule

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/telemetry"
)

// alertScheduleRunFailed is the alert.type (issue #17) emitted as a structured
// OTEL signal when a gated weekly run fails to list or publish, so a backend
// alert can key on a failed scheduled run once an OTLP endpoint is chosen (TBD).
const alertScheduleRunFailed = "schedule.run_failed"

// PendingLister is the seam for "list the reports awaiting publication". It is
// satisfied by *lifecycle.Manager (#10) via its ListPending method; tests inject
// a fake. Kept as a one-method interface so this package does not import the
// storage-backed lifecycle package (and its Wasm-only R2 dependencies).
type PendingLister interface {
	// ListPending returns the ids of every report currently pending, oldest first.
	ListPending(ctx context.Context) ([]string, error)
}

// Publisher is the seam for the publish step (#14), which is not built yet. Run
// hands it the pending ids once the gate says it is time. Implementations turn
// each id into a GitHub issue and mark it published; until #14 lands the default
// [LogPublisher] is wired, so the trigger is exercisable end to end today.
type Publisher interface {
	// Publish takes ownership of the pending report ids for this run. The slice may
	// be empty (a Friday with no pending reports), which implementations should
	// treat as a no-op.
	Publish(ctx context.Context, ids []string) error
}

// Run is the body of the scheduled handler. Given the UTC instant a Cron Trigger
// fired for (Cloudflare supplies it as the event's ScheduledTime), it gates on
// [IsFriday1700Central]: only when the fire is 17:00 Central on a Friday does it
// list the pending reports and hand them to publisher.
//
// The returned bool reports whether the gate fired (whether publish work ran),
// which lets the Worker log the "other" UTC fire as an intentional skip and lets
// tests assert the "runs exactly once per Friday" property. A non-nil error is
// the lister's or publisher's error, wrapped.
func Run(ctx context.Context, scheduledFor time.Time, lister PendingLister, publisher Publisher) (ran bool, err error) {
	if !IsFriday1700Central(scheduledFor) {
		// This is the other candidate UTC fire (or an off-schedule invocation); the
		// sibling cron will fire at the correct Central hour. Do nothing.
		return false, nil
	}
	// Observability (#17): trace the gated run end to end (list + publish). When
	// no telemetry provider rides in ctx (the default until an OTLP endpoint is
	// configured) this is a no-op and behaviour is unchanged; when present, the
	// span becomes the parent of the publisher's publish.run span. A list/publish
	// failure sets the span to Error and emits the alertable run-failed signal.
	tel := telemetry.FromContext(ctx)
	ctx, span := tel.StartSpan(ctx, "schedule.run",
		telemetry.WithSpanKind(telemetry.SpanKindInternal),
		telemetry.WithAttributes(telemetry.String("schedule.scheduled_for", scheduledFor.UTC().Format(time.RFC3339))))
	defer span.End()

	ids, err := lister.ListPending(ctx)
	if err != nil {
		wrapped := fmt.Errorf("schedule: list pending: %w", err)
		span.SetStatus(telemetry.StatusError, wrapped.Error())
		tel.Error(ctx, "schedule: list pending failed",
			append(telemetry.Alert(alertScheduleRunFailed), telemetry.String("error", wrapped.Error()))...)
		return true, wrapped
	}
	span.SetAttributes(telemetry.Int("schedule.pending", len(ids)))
	tel.Info(ctx, "schedule: weekly trigger fired", telemetry.Int("schedule.pending", len(ids)))

	if err := publisher.Publish(ctx, ids); err != nil {
		wrapped := fmt.Errorf("schedule: publish: %w", err)
		span.SetStatus(telemetry.StatusError, wrapped.Error())
		tel.Error(ctx, "schedule: publish run failed",
			append(telemetry.Alert(alertScheduleRunFailed), telemetry.String("error", wrapped.Error()))...)
		return true, wrapped
	}
	span.SetStatus(telemetry.StatusOK, "")
	return true, nil
}

// IsFriday1700Central reports whether instant t falls on Friday at exactly 17:00
// in America/Chicago (Central), correctly handling the CST/CDT DST transition. It
// is the gate that makes the two-UTC-cron scheme fire the publish job exactly
// once each Friday year-round (see the package doc).
//
// It is a pure function of t with no timezone-database or wall-clock dependency,
// so it is exhaustively unit-testable on the host. t may be in any location; it
// is normalized to UTC first.
func IsFriday1700Central(t time.Time) bool {
	c := centralClock(t)
	return c.Weekday() == time.Friday && c.Hour() == 17 && c.Minute() == 0
}

// centralClock returns t rendered as America/Chicago wall-clock time. The result
// is a time.Time whose calendar fields (Weekday, Hour, Minute, ...) read as the
// Central wall clock; its Location remains UTC because the shift is applied by
// arithmetic rather than a *time.Location, so callers must read only its fields,
// never treat it as an absolute instant. This trades a tz-database lookup for a
// hand-computed offset so it works under TinyGo/Wasm.
func centralClock(t time.Time) time.Time {
	u := t.UTC()
	return u.Add(centralOffset(u))
}

// centralOffset is the signed offset from UTC to Central wall-clock time at UTC
// instant u: -5h during Daylight time (CDT), -6h during Standard time (CST).
func centralOffset(u time.Time) time.Duration {
	if centralIsDaylight(u) {
		return -5 * time.Hour
	}
	return -6 * time.Hour
}

// centralIsDaylight reports whether UTC instant u falls in US Central Daylight
// Time. Since 2007 US DST runs from the 2nd Sunday of March at 02:00 local
// (Standard) to the 1st Sunday of November at 02:00 local (Daylight). Expressed
// as absolute UTC instants the boundaries are:
//
//   - spring forward: 2nd Sunday of March, 08:00 UTC (02:00 CST = UTC-6)
//   - fall back:      1st Sunday of November, 07:00 UTC (02:00 CDT = UTC-5)
//
// u is in Daylight time iff it is at or after the spring-forward instant and
// strictly before the fall-back instant. Both boundaries lie in the same UTC
// calendar year as any instant they classify (DST spans March–November), so
// deriving them from u.Year() is correct for every month, including a January
// instant (before spring forward -> Standard) and a December one (after fall
// back -> Standard).
func centralIsDaylight(u time.Time) bool {
	year := u.Year()
	springForward := time.Date(year, time.March, nthSundayOfMonth(year, time.March, 2), 8, 0, 0, 0, time.UTC)
	fallBack := time.Date(year, time.November, nthSundayOfMonth(year, time.November, 1), 7, 0, 0, 0, time.UTC)
	return !u.Before(springForward) && u.Before(fallBack)
}

// nthSundayOfMonth returns the day-of-month (1-based) of the nth Sunday in the
// given month and year, e.g. nthSundayOfMonth(2026, time.March, 2) is the 2nd
// Sunday of March 2026. n is assumed >= 1.
func nthSundayOfMonth(year int, month time.Month, n int) int {
	first := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
	// Days from the 1st to the first Sunday (0 if the 1st is itself a Sunday).
	toFirstSunday := (int(time.Sunday) - int(first.Weekday()) + 7) % 7
	return 1 + toFirstSunday + (n-1)*7
}

// LogPublisher is the default [Publisher] wired into the Worker until the real
// publish step (#14) exists. It publishes nothing; it only logs that the weekly
// trigger fired and how many reports it would have published, so the scheduled
// path is observable end to end before #14 lands. Report ids are opaque handles
// (a timestamp plus random bytes) and carry nothing sensitive, so logging them is
// safe.
type LogPublisher struct {
	// Logf receives the message; it defaults to log.Printf when nil. Tests set it
	// to capture output.
	Logf func(format string, args ...any)
}

// Publish logs the batch it was handed and returns nil.
func (p LogPublisher) Publish(_ context.Context, ids []string) error {
	logf := p.Logf
	if logf == nil {
		logf = log.Printf
	}
	logf("schedule: weekly trigger fired; %d pending report(s) to publish "+
		"(publish step #14 not implemented yet): %v", len(ids), ids)
	return nil
}

// Compile-time check that the default publisher satisfies the seam.
var _ Publisher = LogPublisher{}
