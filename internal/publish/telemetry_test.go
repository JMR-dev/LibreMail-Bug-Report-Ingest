package publish

import (
	"context"
	"fmt"
	"testing"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/telemetry"
)

// telemetryCtx returns a context carrying a fresh telemetry provider plus its
// in-memory exporter for assertions.
func telemetryCtx() (context.Context, *telemetry.MemoryExporter) {
	exp := telemetry.NewMemoryExporter()
	tel := telemetry.New(exp)
	return telemetry.NewContext(context.Background(), tel), exp
}

// TestPublishEmitsRunAndReportSpans: a successful run emits one publish.run span
// and one publish.report child span per report, each with a correlated log.
func TestPublishEmitsRunAndReportSpans(t *testing.T) {
	kr := mustKeyring(t)
	ids := []string{"id-1", "id-2", "id-3"}
	frames := map[string][]byte{}
	for _, id := range ids {
		frames[id] = seal(t, kr, reportJSON(t, sampleReport(id)))
	}
	mc := &mockCreator{}
	pub := newPublisher(mc, kr, &fakeGetter{frames: frames})

	ctx, exp := telemetryCtx()
	if err := pub.Publish(ctx, ids); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	run, ok := exp.SpanByName("publish.run")
	if !ok {
		t.Fatal("no publish.run span")
	}
	if run.Status.Code != telemetry.StatusOK {
		t.Errorf("run status = %d, want OK", run.Status.Code)
	}
	if v, _ := telemetry.Attr(run.Attributes, "publish.published"); v != int64(3) {
		t.Errorf("publish.published = %v, want 3", v)
	}
	if v, _ := telemetry.Attr(run.Attributes, "publish.failed"); v != int64(0) {
		t.Errorf("publish.failed = %v, want 0", v)
	}

	reports := exp.SpansByName("publish.report")
	if len(reports) != len(ids) {
		t.Fatalf("got %d publish.report spans, want %d", len(reports), len(ids))
	}
	for _, rs := range reports {
		// Each report span is a child of the run span, sharing its trace.
		if rs.SpanContext.TraceID != run.SpanContext.TraceID {
			t.Errorf("report span trace %s != run trace %s", rs.SpanContext.TraceID, run.SpanContext.TraceID)
		}
		if rs.ParentSpanID != run.SpanContext.SpanID {
			t.Errorf("report span parent = %s, want run span %s", rs.ParentSpanID, run.SpanContext.SpanID)
		}
		if v, _ := telemetry.Attr(rs.Attributes, "report.outcome"); v != "published" {
			t.Errorf("report outcome = %v, want published", v)
		}
	}

	// One "published" log per report, all correlated to a report span.
	published := 0
	for _, l := range exp.Logs() {
		if v, _ := telemetry.Attr(l.Attributes, "report.outcome"); v == "published" {
			published++
			if !l.SpanContext.IsValid() {
				t.Errorf("published log not correlated to a span")
			}
		}
	}
	if published != len(ids) {
		t.Errorf("got %d published logs, want %d", published, len(ids))
	}
}

// TestPublishCapHitEmitsAlertSignal is the #14 follow-up folded into #17: when
// the per-run cap defers reports, a structured, alertable OTEL signal is emitted
// (a WARN log with alert.type=publish.cap_hit plus counts, and a run-span
// attribute/event) — not merely a human log line.
func TestPublishCapHitEmitsAlertSignal(t *testing.T) {
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
	pub := newPublisher(mc, kr, &fakeGetter{frames: frames})

	ctx, exp := telemetryCtx()
	if err := pub.Publish(ctx, ids); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// The run span records the cap-hit.
	run, _ := exp.SpanByName("publish.run")
	if v, _ := telemetry.Attr(run.Attributes, "publish.cap_hit"); v != true {
		t.Errorf("run span publish.cap_hit = %v, want true", v)
	}
	if v, _ := telemetry.Attr(run.Attributes, "publish.deferred"); v != int64(5) {
		t.Errorf("run span publish.deferred = %v, want 5", v)
	}
	foundEvent := false
	for _, ev := range run.Events {
		if ev.Name == alertCapHit {
			foundEvent = true
		}
	}
	if !foundEvent {
		t.Errorf("run span missing %q event", alertCapHit)
	}

	// The alertable log record.
	var capLog *telemetry.LogRecord
	for i := range exp.Logs() {
		l := exp.Logs()[i]
		if v, _ := telemetry.Attr(l.Attributes, telemetry.AttrAlertType); v == alertCapHit {
			capLog = &l
			break
		}
	}
	if capLog == nil {
		t.Fatal("no cap-hit alert log emitted")
	}
	if capLog.Severity != telemetry.SeverityWarn {
		t.Errorf("cap-hit log severity = %v, want WARN", capLog.Severity)
	}
	if v, ok := telemetry.Attr(capLog.Attributes, telemetry.AttrAlert); !ok || v != true {
		t.Errorf("cap-hit log missing alert marker")
	}
	if v, _ := telemetry.Attr(capLog.Attributes, "publish.deferred"); v != int64(5) {
		t.Errorf("cap-hit log publish.deferred = %v, want 5", v)
	}
	if v, _ := telemetry.Attr(capLog.Attributes, "publish.cap"); v != int64(DefaultMaxPerRun) {
		t.Errorf("cap-hit log publish.cap = %v, want %d", v, DefaultMaxPerRun)
	}
}

// TestPublishRunFailureEmitsAlertSignal: a per-report failure makes the run span
// Error and emits the alert.type=publish.run_failed signal, while the failed
// report gets its own Error span + correlated ERROR log.
func TestPublishRunFailureEmitsAlertSignal(t *testing.T) {
	kr := mustKeyring(t)
	wrongKr := mustKeyring(t) // different key -> decrypt failure on "bad"
	ids := []string{"good-1", "bad", "good-2"}
	frames := map[string][]byte{
		"good-1": seal(t, kr, reportJSON(t, sampleReport("good-1"))),
		"bad":    seal(t, wrongKr, reportJSON(t, sampleReport("bad"))),
		"good-2": seal(t, kr, reportJSON(t, sampleReport("good-2"))),
	}
	mc := &mockCreator{}
	pub := newPublisher(mc, kr, &fakeGetter{frames: frames})

	ctx, exp := telemetryCtx()
	if err := pub.Publish(ctx, ids); err == nil {
		t.Fatal("expected a surfaced error for the decrypt failure")
	}

	run, _ := exp.SpanByName("publish.run")
	if run.Status.Code != telemetry.StatusError {
		t.Errorf("run span status = %d, want Error", run.Status.Code)
	}
	if v, _ := telemetry.Attr(run.Attributes, "publish.failed"); v != int64(1) {
		t.Errorf("publish.failed = %v, want 1", v)
	}

	// A run-failed alert log.
	foundRunAlert := false
	for _, l := range exp.Logs() {
		if v, _ := telemetry.Attr(l.Attributes, telemetry.AttrAlertType); v == alertRunFailed {
			foundRunAlert = true
			if l.Severity != telemetry.SeverityError {
				t.Errorf("run-failed log severity = %v, want ERROR", l.Severity)
			}
		}
	}
	if !foundRunAlert {
		t.Errorf("no %q alert log emitted", alertRunFailed)
	}

	// The failed report span is present and marked failed.
	var failedSpan *telemetry.SpanData
	for i, rs := range exp.SpansByName("publish.report") {
		if v, _ := telemetry.Attr(rs.Attributes, "report.id"); v == "bad" {
			s := exp.SpansByName("publish.report")[i]
			failedSpan = &s
		}
	}
	if failedSpan == nil {
		t.Fatal("no publish.report span for the failed report")
	}
	if failedSpan.Status.Code != telemetry.StatusError {
		t.Errorf("failed report span status = %d, want Error", failedSpan.Status.Code)
	}
	if v, _ := telemetry.Attr(failedSpan.Attributes, "report.outcome"); v != "failed" {
		t.Errorf("failed report outcome = %v, want failed", v)
	}
}

// TestPublishEmptyBatchTraced: an empty run still emits a publish.run span (OK,
// zero attempted) so every scheduled run is observable.
func TestPublishEmptyBatchTraced(t *testing.T) {
	kr := mustKeyring(t)
	mc := &mockCreator{}
	pub := newPublisher(mc, kr, &fakeGetter{})
	ctx, exp := telemetryCtx()
	if err := pub.Publish(ctx, nil); err != nil {
		t.Fatalf("Publish(nil): %v", err)
	}
	run, ok := exp.SpanByName("publish.run")
	if !ok {
		t.Fatal("empty run should still emit a publish.run span")
	}
	if v, _ := telemetry.Attr(run.Attributes, "publish.attempted"); v != int64(0) {
		t.Errorf("publish.attempted = %v, want 0", v)
	}
	// No per-report spans, and the mock was never touched (behaviour unchanged).
	if len(exp.SpansByName("publish.report")) != 0 {
		t.Errorf("empty run emitted report spans")
	}
	if mc.ensureCalls != 0 || len(mc.created) != 0 {
		t.Errorf("empty batch did work: ensureCalls=%d created=%d", mc.ensureCalls, len(mc.created))
	}
}
