package schedule_test

import (
	"context"
	"errors"
	"testing"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/schedule"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/telemetry"
)

func telemetryCtx() (context.Context, *telemetry.MemoryExporter) {
	exp := telemetry.NewMemoryExporter()
	return telemetry.NewContext(context.Background(), telemetry.New(exp)), exp
}

// TestScheduleRunEmitsSpan: a gated run emits a schedule.run span (OK) plus a
// "weekly trigger fired" log recording the pending count.
func TestScheduleRunEmitsSpan(t *testing.T) {
	want := []string{"a", "b"}
	lister := &fakeLister{ids: want}
	pub := &recordingPublisher{}

	ctx, exp := telemetryCtx()
	ran, err := schedule.Run(ctx, fireInstant, lister, pub)
	if err != nil || !ran {
		t.Fatalf("Run = (%v, %v), want (true, nil)", ran, err)
	}

	span, ok := exp.SpanByName("schedule.run")
	if !ok {
		t.Fatal("no schedule.run span")
	}
	if span.Status.Code != telemetry.StatusOK {
		t.Errorf("span status = %d, want OK", span.Status.Code)
	}
	if v, _ := telemetry.Attr(span.Attributes, "schedule.pending"); v != int64(2) {
		t.Errorf("schedule.pending = %v, want 2", v)
	}
	if _, ok := telemetry.Attr(span.Attributes, "schedule.scheduled_for"); !ok {
		t.Errorf("span missing schedule.scheduled_for")
	}

	firedLog := false
	for _, l := range exp.Logs() {
		if l.Body == "schedule: weekly trigger fired" {
			firedLog = true
			if l.SpanContext != span.SpanContext {
				t.Errorf("fired log not correlated to schedule.run span")
			}
		}
	}
	if !firedLog {
		t.Errorf("no weekly-trigger-fired log")
	}
}

// TestScheduleGateClosedEmitsNothing: the sibling (no-op) fire starts no span and
// emits no telemetry — matching its do-nothing contract.
func TestScheduleGateClosedEmitsNothing(t *testing.T) {
	lister := &fakeLister{ids: []string{"x"}}
	pub := &recordingPublisher{}
	ctx, exp := telemetryCtx()

	ran, err := schedule.Run(ctx, notFireInstant, lister, pub)
	if err != nil || ran {
		t.Fatalf("Run = (%v, %v), want (false, nil)", ran, err)
	}
	if len(exp.Spans()) != 0 || len(exp.Logs()) != 0 {
		t.Errorf("gate-closed fire emitted telemetry: %d spans, %d logs", len(exp.Spans()), len(exp.Logs()))
	}
}

// TestScheduleListErrorEmitsAlert: a list failure sets the span to Error, emits
// the alert.type=schedule.run_failed signal, and still returns the wrapped error.
func TestScheduleListErrorEmitsAlert(t *testing.T) {
	sentinel := errors.New("r2 list failed")
	lister := &fakeLister{err: sentinel}
	pub := &recordingPublisher{}
	ctx, exp := telemetryCtx()

	ran, err := schedule.Run(ctx, fireInstant, lister, pub)
	if !ran || !errors.Is(err, sentinel) {
		t.Fatalf("Run = (%v, %v), want (true, wraps sentinel)", ran, err)
	}

	span, _ := exp.SpanByName("schedule.run")
	if span.Status.Code != telemetry.StatusError {
		t.Errorf("span status = %d, want Error", span.Status.Code)
	}
	found := false
	for _, l := range exp.Logs() {
		if v, _ := telemetry.Attr(l.Attributes, telemetry.AttrAlertType); v == "schedule.run_failed" {
			found = true
			if l.Severity != telemetry.SeverityError {
				t.Errorf("alert log severity = %v, want ERROR", l.Severity)
			}
		}
	}
	if !found {
		t.Errorf("no schedule.run_failed alert log")
	}
	if len(pub.batches) != 0 {
		t.Errorf("publisher called despite a list error")
	}
}

// TestScheduleRunParentsPublisher: the ctx handed to the publisher carries the
// schedule.run span, so a publish.run span started from it is a child — the trace
// links the scheduled run to the publish run end to end.
func TestScheduleRunParentsPublisher(t *testing.T) {
	ctx, exp := telemetryCtx()
	var childTrace telemetry.TraceID
	var childParent telemetry.SpanID
	spy := publisherFunc(func(pctx context.Context, _ []string) error {
		tel := telemetry.FromContext(pctx)
		_, span := tel.StartSpan(pctx, "publish.run")
		childTrace = span.SpanContext().TraceID
		sc, _ := telemetry.SpanContextFromContext(pctx)
		childParent = sc.SpanID
		span.End()
		return nil
	})

	ran, err := schedule.Run(ctx, fireInstant, &fakeLister{ids: []string{"a"}}, spy)
	if err != nil || !ran {
		t.Fatalf("Run = (%v, %v), want (true, nil)", ran, err)
	}
	run, _ := exp.SpanByName("schedule.run")
	if childTrace != run.SpanContext.TraceID {
		t.Errorf("publisher's span trace %s != schedule.run trace %s", childTrace, run.SpanContext.TraceID)
	}
	if childParent != run.SpanContext.SpanID {
		t.Errorf("ctx active span in publisher = %s, want schedule.run span %s", childParent, run.SpanContext.SpanID)
	}
}

// publisherFunc adapts a function to schedule.Publisher.
type publisherFunc func(context.Context, []string) error

func (f publisherFunc) Publish(ctx context.Context, ids []string) error { return f(ctx, ids) }
