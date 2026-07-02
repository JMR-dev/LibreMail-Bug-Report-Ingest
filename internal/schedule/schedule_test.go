package schedule_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	// Embed the IANA tz database into the test binary so
	// time.LoadLocation("America/Chicago") works on every host (notably Windows,
	// which has no system zoneinfo). This is a TEST-only import: it never reaches
	// the Wasm Worker build, whose gate is the hand-rolled rule under test. It lets
	// these tests cross-check that hand-rolled rule against the authoritative zone.
	_ "time/tzdata"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/schedule"
)

// utc is a terse constructor for a UTC instant.
func utc(y int, mo time.Month, d, h, mi int) time.Time {
	return time.Date(y, mo, d, h, mi, 0, 0, time.UTC)
}

// TestIsFriday1700Central is the ticket's core acceptance: the gate returns true
// only at 17:00 America/Chicago on Fridays, across both DST seasons, the days
// bracketing each transition, wrong hours, wrong minutes, and non-Fridays. Every
// UTC instant below was verified against the real America/Chicago zone.
func TestIsFriday1700Central(t *testing.T) {
	cases := []struct {
		name string
		in   time.Time
		want bool
	}{
		// --- Summer, CDT (UTC-5): 17:00 Central == 22:00 UTC. Fri 2026-07-10. ---
		{"CDT friday 22:00 UTC is 17:00 Central", utc(2026, time.July, 10, 22, 0), true},
		// The OTHER candidate cron hour must be false in summer, so work runs once.
		{"CDT friday 23:00 UTC is 18:00 Central", utc(2026, time.July, 10, 23, 0), false},
		{"CDT friday 21:00 UTC is 16:00 Central", utc(2026, time.July, 10, 21, 0), false},

		// --- Winter, CST (UTC-6): 17:00 Central == 23:00 UTC. Fri 2026-01-09. ---
		{"CST friday 23:00 UTC is 17:00 Central", utc(2026, time.January, 9, 23, 0), true},
		// The OTHER candidate cron hour must be false in winter, so work runs once.
		{"CST friday 22:00 UTC is 16:00 Central", utc(2026, time.January, 9, 22, 0), false},
		{"CST friday 00:00 UTC sat is 18:00 Central fri", utc(2026, time.January, 10, 0, 0), false},

		// --- Around spring forward (2026-03-08 02:00). Fri before is CST, after CDT. ---
		{"friday before spring-forward is CST -> 23:00 UTC", utc(2026, time.March, 6, 23, 0), true},
		{"friday before spring-forward: 22:00 UTC is 16:00", utc(2026, time.March, 6, 22, 0), false},
		{"friday after spring-forward is CDT -> 22:00 UTC", utc(2026, time.March, 13, 22, 0), true},
		{"friday after spring-forward: 23:00 UTC is 18:00", utc(2026, time.March, 13, 23, 0), false},

		// --- Around fall back (2026-11-01 02:00). Fri before is CDT, after CST. ---
		{"friday before fall-back is CDT -> 22:00 UTC", utc(2026, time.October, 30, 22, 0), true},
		{"friday before fall-back: 23:00 UTC is 18:00", utc(2026, time.October, 30, 23, 0), false},
		{"friday after fall-back is CST -> 23:00 UTC", utc(2026, time.November, 6, 23, 0), true},
		{"friday after fall-back: 22:00 UTC is 16:00", utc(2026, time.November, 6, 22, 0), false},

		// --- Non-Fridays at the exact Central 17:00 hour must be false. ---
		{"thursday 17:00 Central (CDT)", utc(2026, time.July, 9, 22, 0), false},
		{"saturday 17:00 Central (CDT)", utc(2026, time.July, 11, 22, 0), false},
		{"thursday 17:00 Central (CST)", utc(2026, time.January, 8, 23, 0), false},

		// --- Right hour+weekday but wrong minute must be false (17:00 exactly). ---
		{"CDT friday 22:30 UTC is 17:30 Central", utc(2026, time.July, 10, 22, 30), false},
		{"CST friday 23:01 UTC is 17:01 Central", utc(2026, time.January, 9, 23, 1), false},

		// --- A different year's transition, to prove nthSunday isn't hard-coded. ---
		// 2027 spring forward is 2027-03-14; Fri 2027-03-12 is still CST.
		{"2027 friday before spring-forward is CST", utc(2027, time.March, 12, 23, 0), true},
		{"2027 friday before spring-forward: 22:00 is 16:00", utc(2027, time.March, 12, 22, 0), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := schedule.IsFriday1700Central(tc.in); got != tc.want {
				t.Errorf("IsFriday1700Central(%s) = %v, want %v",
					tc.in.Format(time.RFC3339), got, tc.want)
			}
		})
	}
}

// TestGateInputLocationIndependent proves the gate depends only on the instant,
// not on the time.Time's Location: the same absolute moment expressed in a
// non-UTC zone yields the same answer.
func TestGateInputLocationIndependent(t *testing.T) {
	chi := mustLoadChicago(t)
	// 17:00 America/Chicago on Fri 2026-07-10, expressed in Central rather than UTC.
	central := time.Date(2026, time.July, 10, 17, 0, 0, 0, chi)
	if !schedule.IsFriday1700Central(central) {
		t.Errorf("gate should be true for 17:00 Central expressed in the Central zone")
	}
	// And the equivalent UTC instant agrees.
	if !schedule.IsFriday1700Central(central.UTC()) {
		t.Errorf("gate should be true for the same instant in UTC")
	}
}

// TestGateFiresExactlyOncePerFriday proves the two-UTC-cron scheme does the work
// exactly once each Friday year-round: for every Friday across several years,
// exactly one of the two candidate cron hours (22:00 and 23:00 UTC) passes the
// gate — never zero, never both — regardless of which side of a DST boundary the
// Friday falls on.
func TestGateFiresExactlyOncePerFriday(t *testing.T) {
	fridays := 0
	for d := utc(2024, time.January, 1, 0, 0); d.Year() < 2031; d = d.AddDate(0, 0, 1) {
		if d.Weekday() != time.Friday {
			continue
		}
		fridays++
		hit22 := schedule.IsFriday1700Central(utc(d.Year(), d.Month(), d.Day(), 22, 0))
		hit23 := schedule.IsFriday1700Central(utc(d.Year(), d.Month(), d.Day(), 23, 0))
		count := 0
		if hit22 {
			count++
		}
		if hit23 {
			count++
		}
		if count != 1 {
			t.Errorf("Friday %s: gate passed for %d of the two cron hours (22:00=%v, 23:00=%v), want exactly 1",
				d.Format("2006-01-02"), count, hit22, hit23)
		}
	}
	if fridays < 300 {
		t.Fatalf("sanity: only iterated %d Fridays, expected ~365", fridays)
	}
}

// TestGateMatchesIANAAcrossDSTBoundary is the exhaustive DST verification the
// ticket asks for "without waiting for a real DST change": it sweeps every 30
// minutes across 20 years and asserts the hand-rolled gate agrees with the real
// America/Chicago zone at every instant — including both transition weekends each
// year. If the hand-rolled CST/CDT rule ever drifts from IANA, this fails.
func TestGateMatchesIANAAcrossDSTBoundary(t *testing.T) {
	chi := mustLoadChicago(t)
	mismatches := 0
	var firstMismatch string
	for tt := utc(2015, time.January, 1, 0, 0); tt.Year() < 2035; tt = tt.Add(30 * time.Minute) {
		inChi := tt.In(chi)
		want := inChi.Weekday() == time.Friday && inChi.Hour() == 17 && inChi.Minute() == 0
		got := schedule.IsFriday1700Central(tt)
		if want != got {
			mismatches++
			if firstMismatch == "" {
				firstMismatch = tt.Format(time.RFC3339) + " (Central " + inChi.Format(time.RFC3339) + ")"
			}
		}
	}
	if mismatches != 0 {
		t.Errorf("hand-rolled gate disagreed with America/Chicago at %d instants; first: %s",
			mismatches, firstMismatch)
	}
}

// --- Run orchestration tests (mock lifecycle + mock publisher) ---

// fakeLister is a mock PendingLister recording call count and returning canned ids/err.
type fakeLister struct {
	ids   []string
	err   error
	calls int
}

func (f *fakeLister) ListPending(context.Context) ([]string, error) {
	f.calls++
	return f.ids, f.err
}

// recordingPublisher captures the id batches handed to it.
type recordingPublisher struct {
	batches [][]string
	err     error
}

func (p *recordingPublisher) Publish(_ context.Context, ids []string) error {
	p.batches = append(p.batches, ids)
	return p.err
}

// A Friday 17:00 Central instant (CDT), reused by the Run tests.
var fireInstant = utc(2026, time.July, 10, 22, 0)

// notFireInstant is the sibling UTC cron hour on the same Friday: 18:00 Central.
var notFireInstant = utc(2026, time.July, 10, 23, 0)

// TestRunPublishesPendingWhenGateFires is the ticket's second acceptance for the
// handler: when it is Friday 17:00 Central, Run lists pending and hands the
// publisher exactly those ids, once.
func TestRunPublishesPendingWhenGateFires(t *testing.T) {
	want := []string{"20260703T120000-aaaa", "20260704T090000-bbbb", "20260705T221530-cccc"}
	lister := &fakeLister{ids: want}
	pub := &recordingPublisher{}

	ran, err := schedule.Run(context.Background(), fireInstant, lister, pub)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !ran {
		t.Fatalf("Run ran=false at Friday 17:00 Central, want true")
	}
	if lister.calls != 1 {
		t.Errorf("ListPending called %d times, want 1", lister.calls)
	}
	if len(pub.batches) != 1 {
		t.Fatalf("Publish called %d times, want 1", len(pub.batches))
	}
	if !slices.Equal(pub.batches[0], want) {
		t.Errorf("Publish got ids %v, want exactly the pending ids %v", pub.batches[0], want)
	}
}

// TestRunSkipsWhenGateClosed proves the sibling cron fire (18:00 Central) does no
// work: neither the lister nor the publisher is touched. Combined with the
// gate-fires test above, this is what makes publishing happen exactly once per
// Friday from two UTC crons.
func TestRunSkipsWhenGateClosed(t *testing.T) {
	lister := &fakeLister{ids: []string{"should-not-be-listed"}}
	pub := &recordingPublisher{}

	ran, err := schedule.Run(context.Background(), notFireInstant, lister, pub)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ran {
		t.Errorf("Run ran=true at the sibling cron hour (18:00 Central), want false")
	}
	if lister.calls != 0 {
		t.Errorf("ListPending called %d times on a skipped fire, want 0", lister.calls)
	}
	if len(pub.batches) != 0 {
		t.Errorf("Publish called on a skipped fire, want not called")
	}
}

// TestRunPublishesEmptyBatch checks that a Friday with no pending reports still
// invokes the publisher (with an empty slice), so #14 sees every scheduled run.
func TestRunPublishesEmptyBatch(t *testing.T) {
	lister := &fakeLister{ids: nil}
	pub := &recordingPublisher{}

	ran, err := schedule.Run(context.Background(), fireInstant, lister, pub)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !ran {
		t.Errorf("ran=false, want true")
	}
	if len(pub.batches) != 1 {
		t.Fatalf("Publish called %d times, want 1 (even for an empty batch)", len(pub.batches))
	}
	if len(pub.batches[0]) != 0 {
		t.Errorf("Publish got %v, want empty batch", pub.batches[0])
	}
}

// TestRunPropagatesListerError surfaces a lifecycle failure and does not publish.
func TestRunPropagatesListerError(t *testing.T) {
	sentinel := errors.New("r2 list failed")
	lister := &fakeLister{err: sentinel}
	pub := &recordingPublisher{}

	ran, err := schedule.Run(context.Background(), fireInstant, lister, pub)
	if !ran {
		t.Errorf("ran=false, want true (the gate fired before the error)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Run err = %v, want it to wrap %v", err, sentinel)
	}
	if len(pub.batches) != 0 {
		t.Errorf("Publish called despite a list error, want not called")
	}
}

// TestRunPropagatesPublisherError surfaces a publish failure to the caller (the
// Worker), which lets the runtime record the scheduled invocation as failed.
func TestRunPropagatesPublisherError(t *testing.T) {
	sentinel := errors.New("publish failed")
	lister := &fakeLister{ids: []string{"id-1"}}
	pub := &recordingPublisher{err: sentinel}

	ran, err := schedule.Run(context.Background(), fireInstant, lister, pub)
	if !ran {
		t.Errorf("ran=false, want true")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Run err = %v, want it to wrap %v", err, sentinel)
	}
}

// TestLogPublisherDefault covers the no-op default seam wired until #14: it
// reports the batch it was handed and never errors.
func TestLogPublisherDefault(t *testing.T) {
	var logged string
	pub := schedule.LogPublisher{Logf: func(format string, args ...any) {
		logged = format
	}}
	if err := pub.Publish(context.Background(), []string{"a", "b"}); err != nil {
		t.Fatalf("LogPublisher.Publish: %v", err)
	}
	if logged == "" {
		t.Error("LogPublisher did not log anything")
	}
}

func mustLoadChicago(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("America/Chicago")
	if err != nil {
		t.Fatalf("LoadLocation(America/Chicago): %v (time/tzdata should make this always succeed)", err)
	}
	return loc
}
