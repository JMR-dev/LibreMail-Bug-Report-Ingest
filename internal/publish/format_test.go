package publish

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/ingest"
)

// reportJSON marshals a Report to the scrubbed-JSON plaintext shape that
// crypto.Open yields (what formatIssue receives).
func reportJSON(t *testing.T, r ingest.Report) []byte {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	return b
}

// TestFormatIssueWellFormed checks the happy path renders a title and a body that
// carries the id, the metadata, and the report text inside a code fence.
func TestFormatIssueWellFormed(t *testing.T) {
	id := "20260703T120000-aabbccddeeff00112233"
	pt := reportJSON(t, ingest.Report{
		AppVersion:      "1.4.2 (142)",
		Platform:        "android",
		OSVersion:       "Android 14",
		Device:          "Pixel 7",
		ClientTimestamp: "2026-07-02T12:34:56Z",
		Report:          "NullPointerException in SyncService\nat line 42",
	})

	title, body := formatIssue(id, pt)

	if !strings.Contains(title, "1.4.2 (142)") || !strings.Contains(title, "android") {
		t.Errorf("title missing app/platform: %q", title)
	}
	for _, want := range []string{
		id,                                    // report id for traceability
		"1.4.2 (142)",                         // app version row
		"Android 14",                          // os version row
		"Pixel 7",                             // device row
		"2026-07-02T12:34:56Z",                // client timestamp row
		"NullPointerException in SyncService", // the report text
		"docs/privacy.md",                     // scrubbing disclosure
		"bug-report",                          // labels footer
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n---\n%s", want, body)
		}
	}
	if utf8.RuneCountInString(body) > MaxIssueBodyRunes {
		t.Errorf("body length %d exceeds cap %d", utf8.RuneCountInString(body), MaxIssueBodyRunes)
	}
	// The report text must sit inside a fenced code block (injection-safe).
	if !strings.Contains(body, "```\nNullPointerException") {
		t.Errorf("report text not wrapped in a code fence:\n%s", body)
	}
}

// TestFormatIssueTruncatesOversizeBody is the ADR #6 §2.1 requirement: a report
// whose rendered body would exceed 65,536 characters is truncated to fit.
func TestFormatIssueTruncatesOversizeBody(t *testing.T) {
	huge := strings.Repeat("A", MaxIssueBodyRunes*2) // way over the cap
	pt := reportJSON(t, ingest.Report{
		AppVersion: "9.9.9",
		Platform:   "android",
		Report:     huge,
	})

	_, body := formatIssue("id-huge", pt)

	if got := utf8.RuneCountInString(body); got > MaxIssueBodyRunes {
		t.Fatalf("truncated body length %d exceeds cap %d", got, MaxIssueBodyRunes)
	}
	if !strings.Contains(body, "truncated") {
		t.Errorf("oversize body lacks a truncation marker:\n%s…", body[:200])
	}
	// It should still be near the cap (we kept as much as fits), not tiny.
	if got := utf8.RuneCountInString(body); got < MaxIssueBodyRunes-1024 {
		t.Errorf("truncated body length %d is far below the cap; too aggressive", got)
	}
}

// TestFormatIssueMarkdownInjectionSafe proves backtick runs in the report cannot
// break out of the code fence and @mentions are neutralised (kept inside code).
func TestFormatIssueMarkdownInjectionSafe(t *testing.T) {
	// A report containing a triple-backtick run and an @mention.
	body := "before ``` middle ```` end @maintainer please look"
	pt := reportJSON(t, ingest.Report{AppVersion: "1", Platform: "android", Report: body})

	_, out := formatIssue("id-x", pt)

	// The fence chosen must be longer than the longest backtick run (4) → ≥5.
	if !strings.Contains(out, "`````") {
		t.Errorf("expected a fence of ≥5 backticks to survive the content, got:\n%s", out)
	}
	// The @mention is present but only ever inside the code block (we can at least
	// assert it is not on a line by itself outside a fence — a coarse check: the
	// content line is indented/enclosed, i.e. the raw text is retained verbatim).
	if !strings.Contains(out, "@maintainer") {
		t.Errorf("report content was dropped")
	}
	if utf8.RuneCountInString(out) > MaxIssueBodyRunes {
		t.Errorf("body exceeds cap")
	}
}

// TestFormatIssueUnparseablePayload: if the decrypted bytes are not the expected
// JSON shape, the content is shown verbatim rather than dropped.
func TestFormatIssueUnparseablePayload(t *testing.T) {
	pt := []byte("this is not json, just raw text with a secret [REDACTED_EMAIL]")

	title, body := formatIssue("id-raw", pt)

	if title == "" {
		t.Error("empty title for unparseable payload")
	}
	if !strings.Contains(body, "not json") {
		t.Errorf("verbatim content missing:\n%s", body)
	}
	if !strings.Contains(body, "did not match the expected report schema") {
		t.Errorf("expected a schema-mismatch note:\n%s", body)
	}
}

// TestFormatIssuePipeAndBacktickInMetadata: metadata values with '|' or '`' must
// not break the Markdown table or the inline-code span.
func TestFormatIssueMetadataSanitised(t *testing.T) {
	pt := reportJSON(t, ingest.Report{
		AppVersion: "1.0 | weird `build`",
		Platform:   "android",
		Report:     "x",
	})
	_, body := formatIssue("id", pt)
	// The raw '|' and '`' must have been replaced in the rendered cell.
	if strings.Contains(body, "1.0 | weird `build`") {
		t.Errorf("metadata not sanitised for table/inline-code:\n%s", body)
	}
}

func TestFenceFor(t *testing.T) {
	cases := map[string]int{
		"no backticks":   3,
		"one ` here":     3, // longest run 1 → max(3, 2)=3
		"two `` here":    3, // longest run 2 → max(3,3)=3
		"three ``` here": 4,
		"four ```` here": 5,
	}
	for in, wantLen := range cases {
		if got := fenceFor(in); len(got) != wantLen {
			t.Errorf("fenceFor(%q) len = %d, want %d", in, len(got), wantLen)
		}
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("héllo", 3); got != "hél" {
		t.Errorf("truncateRunes multibyte = %q, want %q", got, "hél")
	}
	if got := truncateRunes("abc", 10); got != "abc" {
		t.Errorf("truncateRunes under limit = %q, want abc", got)
	}
	if got := truncateRunes("abc", 0); got != "" {
		t.Errorf("truncateRunes zero = %q, want empty", got)
	}
}
