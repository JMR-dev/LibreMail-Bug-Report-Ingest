package publish

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/ingest"
)

// MaxIssueBodyRunes is GitHub's hard cap on an issue body (ADR #6 §2.1 note:
// "GitHub issue bodies are capped at 65,536 characters"). formatIssue keeps the
// rendered body at or below this, truncating the free-text report if needed.
const MaxIssueBodyRunes = 65536

// maxTitleRunes keeps titles well under GitHub's 256-char limit.
const maxTitleRunes = 200

// truncationMarker is appended to a report whose text had to be cut to fit.
const truncationMarker = "\n\n[… truncated: report exceeded GitHub's 65,536-character issue body limit …]"

// formatIssue renders a decrypted (scrubbed) report into a GitHub issue title and
// body. plaintext is the JSON produced at ingest (an ingest.Report shape) after
// PII scrubbing; if it does not parse as that shape, the raw text is embedded
// verbatim so nothing is silently dropped.
//
// # Markdown-injection safety
//
// The report is user-supplied (scrubbed, but not trusted): its free text is
// wrapped in a fenced code block (with a fence long enough to survive any backtick
// run in the content) and metadata values are wrapped in inline code, so @mentions
// and links in a report cannot notify users or render as active Markdown in the
// issue. The body is finally clamped to MaxIssueBodyRunes runes as a backstop.
func formatIssue(id string, plaintext []byte) (title, body string) {
	var rep ingest.Report
	parsed := json.Unmarshal(plaintext, &rep) == nil

	title = buildTitle(rep, parsed)
	body = buildBody(id, rep, plaintext, parsed)
	return title, body
}

// buildTitle produces a short, human-readable issue title.
func buildTitle(rep ingest.Report, parsed bool) string {
	if !parsed {
		return "Automated bug report"
	}
	app := oneLine(rep.AppVersion)
	platform := oneLine(rep.Platform)
	title := "Bug report"
	if app != "" {
		title += ": " + app
	}
	if platform != "" {
		title += " on " + platform
	}
	return truncateRunes(title, maxTitleRunes)
}

// buildBody assembles the Markdown body, fitting the report text within the rune
// budget left after the fixed sections.
func buildBody(id string, rep ingest.Report, plaintext []byte, parsed bool) string {
	var head strings.Builder
	head.WriteString("This issue was filed automatically by the LibreMail bug-report ingest pipeline ")
	head.WriteString("(opt-in debug reports from the app). PII was best-effort scrubbed before storage; ")
	head.WriteString("see `docs/privacy.md`.\n\n")
	head.WriteString("**Report ID:** `")
	head.WriteString(sanitizeCode(id))
	head.WriteString("`\n\n")

	// The free-text report to embed: the report field when the payload parsed,
	// otherwise the whole decrypted blob (so a schema drift never loses content).
	reportText := string(plaintext)
	if parsed {
		head.WriteString(metadataTable(rep))
		head.WriteString("\n### Report\n\n")
		reportText = rep.Report
	} else {
		head.WriteString("_Payload did not match the expected report schema; showing the decrypted content verbatim._\n\n")
		head.WriteString("### Decrypted content\n\n")
	}

	const footer = "\n\n---\nLabels: `bug-report`, `automated`, `needs-triage`.\n"

	fence := fenceFor(reportText)
	// Budget for the report text = cap − (everything else) − the two fence lines
	// and their newlines.
	overhead := utf8.RuneCountInString(head.String()) +
		utf8.RuneCountInString(footer) +
		2*utf8.RuneCountInString(fence) +
		2 // the two newlines wrapping the fenced content
	budget := MaxIssueBodyRunes - overhead

	if utf8.RuneCountInString(reportText) > budget {
		keep := budget - utf8.RuneCountInString(truncationMarker)
		if keep < 0 {
			keep = 0
		}
		reportText = truncateRunes(reportText, keep) + truncationMarker
	}

	var b strings.Builder
	b.WriteString(head.String())
	b.WriteString(fence)
	b.WriteString("\n")
	b.WriteString(reportText)
	b.WriteString("\n")
	b.WriteString(fence)
	b.WriteString(footer)

	// Backstop: never exceed the cap even if the fixed sections themselves are
	// unexpectedly large.
	return truncateRunes(b.String(), MaxIssueBodyRunes)
}

// metadataTable renders the report's non-empty metadata fields as a Markdown
// table with values in inline code (neutralising '|' and @mentions).
func metadataTable(rep ingest.Report) string {
	rows := []struct{ label, value string }{
		{"App version", rep.AppVersion},
		{"Platform", rep.Platform},
		{"OS version", rep.OSVersion},
		{"Device", rep.Device},
		{"Client timestamp", rep.ClientTimestamp},
	}
	var b strings.Builder
	b.WriteString("| Field | Value |\n| --- | --- |\n")
	for _, r := range rows {
		v := oneLine(r.value)
		if v == "" {
			continue
		}
		b.WriteString("| ")
		b.WriteString(r.label)
		b.WriteString(" | `")
		b.WriteString(sanitizeCode(v))
		b.WriteString("` |\n")
	}
	return b.String()
}

// fenceFor returns a run of backticks one longer than the longest backtick run in
// s (minimum 3), so s can be embedded in a fenced code block without the fence
// being closed early by backticks inside the content.
func fenceFor(s string) string {
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	n := longest + 1
	if n < 3 {
		n = 3
	}
	return strings.Repeat("`", n)
}

// oneLine collapses a metadata value to a single trimmed line (newlines and other
// control characters become spaces), keeping the issue tidy.
func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 {
			return -1 // drop other control characters
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// sanitizeCode makes a value safe to place inside an inline-code span within a
// Markdown table cell: backticks (which would close the span) become quotes and
// pipes (which would split the cell) become slashes.
func sanitizeCode(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.ReplaceAll(s, "|", "/")
	return s
}

// truncateRunes returns s limited to at most n runes (n < 0 is treated as 0).
func truncateRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	i, count := 0, 0
	for i = range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}
