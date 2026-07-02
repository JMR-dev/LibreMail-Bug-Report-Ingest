package telemetry

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fixedClock returns a clock function yielding a fixed instant.
func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// seqIDs returns deterministic id generators: trace ids 0x..01, 0x..02, ...;
// span ids likewise, so tests can assert exact correlation.
func seqIDs() (func() TraceID, func() SpanID) {
	var tn, sn byte
	return func() TraceID {
			tn++
			return TraceID{15: tn}
		}, func() SpanID {
			sn++
			return SpanID{7: sn}
		}
}

func testProvider(t *testing.T) (*Telemetry, *MemoryExporter) {
	t.Helper()
	exp := NewMemoryExporter()
	nt, ns := seqIDs()
	tel := New(exp,
		WithClock(fixedClock(time.Unix(1_700_000_000, 0).UTC())),
		WithIDGenerator(nt, ns))
	return tel, exp
}

func TestStartSpanExportsSpanData(t *testing.T) {
	tel, exp := testProvider(t)
	ctx, span := tel.StartSpan(context.Background(), "ingest.request",
		WithSpanKind(SpanKindServer),
		WithAttributes(String("http.request.method", "POST")))
	span.SetAttributes(Int("http.response.status_code", 202))
	span.SetStatus(StatusOK, "")
	span.End()
	_ = ctx

	spans := exp.Spans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	s := spans[0]
	if s.Name != "ingest.request" {
		t.Errorf("name = %q, want ingest.request", s.Name)
	}
	if s.Kind != SpanKindServer {
		t.Errorf("kind = %d, want %d", s.Kind, SpanKindServer)
	}
	if !s.SpanContext.IsValid() {
		t.Errorf("span context invalid: %+v", s.SpanContext)
	}
	if !s.ParentSpanID.IsZero() {
		t.Errorf("root span should have zero parent, got %s", s.ParentSpanID)
	}
	if s.Status.Code != StatusOK {
		t.Errorf("status = %d, want OK", s.Status.Code)
	}
	if v, ok := Attr(s.Attributes, "http.request.method"); !ok || v != "POST" {
		t.Errorf("method attr = %v (present=%v), want POST", v, ok)
	}
	if v, ok := Attr(s.Attributes, "http.response.status_code"); !ok || v != int64(202) {
		t.Errorf("status_code attr = %v (present=%v), want int64 202", v, ok)
	}
}

func TestNestedSpanSharesTraceAndParents(t *testing.T) {
	tel, exp := testProvider(t)
	ctx, parent := tel.StartSpan(context.Background(), "publish.run")
	_, child := tel.StartSpan(ctx, "publish.report")
	child.End()
	parent.End()

	spans := exp.Spans()
	if len(spans) != 2 {
		t.Fatalf("got %d spans, want 2", len(spans))
	}
	// Export order: child ended first.
	c, p := spans[0], spans[1]
	if c.SpanContext.TraceID != p.SpanContext.TraceID {
		t.Errorf("child/parent trace ids differ: %s vs %s", c.SpanContext.TraceID, p.SpanContext.TraceID)
	}
	if c.ParentSpanID != p.SpanContext.SpanID {
		t.Errorf("child parent = %s, want parent span id %s", c.ParentSpanID, p.SpanContext.SpanID)
	}
	if p.SpanContext.SpanID == c.SpanContext.SpanID {
		t.Errorf("child and parent share a span id: %s", c.SpanContext.SpanID)
	}
}

func TestLogCorrelatesWithActiveSpan(t *testing.T) {
	tel, exp := testProvider(t)
	ctx, span := tel.StartSpan(context.Background(), "ingest.request")
	tel.Info(ctx, "ingest request accepted", String("ingest.outcome", "accepted"))
	span.End()

	logs := exp.Logs()
	if len(logs) != 1 {
		t.Fatalf("got %d logs, want 1", len(logs))
	}
	l := logs[0]
	if l.Severity != SeverityInfo {
		t.Errorf("severity = %v, want INFO", l.Severity)
	}
	if l.Body != "ingest request accepted" {
		t.Errorf("body = %q", l.Body)
	}
	if l.SpanContext != span.SpanContext() {
		t.Errorf("log span context %+v != span %+v (not correlated)", l.SpanContext, span.SpanContext())
	}
	if v, ok := Attr(l.Attributes, "ingest.outcome"); !ok || v != "accepted" {
		t.Errorf("outcome attr = %v (present=%v)", v, ok)
	}
}

func TestLogWithoutSpanHasNoCorrelation(t *testing.T) {
	tel, exp := testProvider(t)
	tel.Warn(context.Background(), "standalone warning")
	logs := exp.Logs()
	if len(logs) != 1 {
		t.Fatalf("got %d logs, want 1", len(logs))
	}
	if logs[0].SpanContext.IsValid() {
		t.Errorf("log outside a span should not correlate, got %+v", logs[0].SpanContext)
	}
	if logs[0].Severity != SeverityWarn {
		t.Errorf("severity = %v, want WARN", logs[0].Severity)
	}
}

func TestRecordError(t *testing.T) {
	tel, exp := testProvider(t)
	_, span := tel.StartSpan(context.Background(), "op")
	span.RecordError(errors.New("boom"))
	span.End()
	s := exp.Spans()[0]
	if s.Status.Code != StatusError {
		t.Errorf("status = %d, want Error", s.Status.Code)
	}
	if len(s.Events) != 1 || s.Events[0].Name != "exception" {
		t.Fatalf("want one exception event, got %+v", s.Events)
	}
	if v, ok := Attr(s.Events[0].Attributes, "exception.message"); !ok || v != "boom" {
		t.Errorf("exception.message = %v (present=%v)", v, ok)
	}
}

// TestDisabledProviderIsNoop is the behaviour-preserving guarantee: a nil
// provider (what FromContext returns when telemetry is not configured) and a
// New(nil) provider must be fully no-op and never panic, and StartSpan must
// return the context unchanged so downstream behaviour is identical.
func TestDisabledProviderIsNoop(t *testing.T) {
	for _, tc := range []struct {
		name string
		tel  *Telemetry
	}{
		{"nil provider", nil},
		{"nil exporter", New(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.tel.Enabled() {
				t.Fatal("provider should report disabled")
			}
			base := context.Background()
			ctx, span := tc.tel.StartSpan(base, "op", WithSpanKind(SpanKindServer))
			if ctx != base {
				t.Error("disabled StartSpan must return the context unchanged")
			}
			if span != nil {
				t.Error("disabled StartSpan must return a nil span")
			}
			// None of these must panic on the nil span / disabled provider.
			span.SetAttributes(String("k", "v"))
			span.SetStatus(StatusError, "x")
			span.RecordError(errors.New("e"))
			span.AddEvent("ev")
			span.End()
			if sc := span.SpanContext(); sc.IsValid() {
				t.Error("nil span should have an invalid span context")
			}
			tc.tel.Info(ctx, "msg")
			tc.tel.Warn(ctx, "msg")
			tc.tel.Error(ctx, "msg")
		})
	}
}

func TestFromContextRoundTrip(t *testing.T) {
	tel, _ := testProvider(t)
	ctx := NewContext(context.Background(), tel)
	if got := FromContext(ctx); got != tel {
		t.Errorf("FromContext = %p, want %p", got, tel)
	}
	if got := FromContext(context.Background()); got != nil {
		t.Errorf("FromContext on a bare context = %p, want nil", got)
	}
}

func TestAlertHelper(t *testing.T) {
	kvs := Alert("publish.cap_hit")
	if len(kvs) != 2 {
		t.Fatalf("Alert returned %d attrs, want 2", len(kvs))
	}
	if v, ok := Attr(kvs, AttrAlert); !ok || v != true {
		t.Errorf("alert marker = %v (present=%v), want true", v, ok)
	}
	if v, ok := Attr(kvs, AttrAlertType); !ok || v != "publish.cap_hit" {
		t.Errorf("alert.type = %v (present=%v)", v, ok)
	}
}

func TestSeverityString(t *testing.T) {
	for sev, want := range map[Severity]string{
		SeverityInfo:  "INFO",
		SeverityWarn:  "WARN",
		SeverityError: "ERROR",
	} {
		if got := sev.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", sev, got, want)
		}
	}
}

func TestEndIsIdempotent(t *testing.T) {
	tel, exp := testProvider(t)
	_, span := tel.StartSpan(context.Background(), "op")
	span.End()
	span.End() // second End must not double-export
	if got := len(exp.Spans()); got != 1 {
		t.Errorf("got %d spans after double End, want 1", got)
	}
}
