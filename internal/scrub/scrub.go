// Package scrub performs a BEST-EFFORT PII redaction pass over raw bug-report
// payloads before they are persisted.
//
// # Best-effort, not a guarantee
//
// This package makes a good-faith attempt to remove obviously sensitive data
// (email addresses, auth tokens/secrets, IP addresses, and — very weakly —
// personal names). It is a defence-in-depth layer, NOT a guarantee: it WILL
// miss things and it MAY over-redact non-sensitive data that merely resembles a
// sensitive pattern. Callers and operators MUST NOT treat a scrubbed payload as
// certified free of PII. The authoritative statement of this limitation lives in
// the privacy documentation (see issue #12); keep this comment aligned with it.
//
// # Why regex/heuristic based
//
// The bug-report payload schema is not finalised (see issue #7), so redaction
// operates on raw text/bytes using regular expressions and lightweight
// heuristics. This keeps it schema-agnostic: it works the same whether the
// payload is JSON, form-encoded, a log excerpt, or free text, and it can be
// dropped in front of storage (see issue #9) without a schema dependency.
//
// # Design
//
// Redaction is expressed as an ordered list of (regexp, replacement) rules
// grouped into categories. Each rule MASKS rather than deletes — matched spans
// are replaced with a bracketed placeholder such as "[REDACTED_EMAIL]" — so the
// surrounding structure of the payload is preserved for triage. The categories
// are exposed individually (RedactEmails, RedactTokens, RedactIPs, RedactNames)
// so a caller can compose only the passes it wants; ScrubString / Scrub run all
// of them in an order chosen to avoid rules clobbering each other's output.
//
// The pass is idempotent: running it twice yields the same result, because the
// placeholders it emits are constructed so that no rule matches them.
//
// This package carries no build constraints, so it compiles and is unit-tested
// with the standard Go toolchain on the host and is reused verbatim by the
// Cloudflare Worker Wasm build.
package scrub

import "regexp"

// Placeholder tokens substituted in place of redacted spans. They are exported
// so that downstream code (e.g. the storage layer in #9) and tests can refer to
// them without hard-coding string literals. Each is deliberately bracketed and
// upper-snake-case so that no redaction rule re-matches it, keeping the pass
// idempotent.
const (
	PlaceholderEmail = "[REDACTED_EMAIL]"
	PlaceholderToken = "[REDACTED_TOKEN]"
	PlaceholderAuth  = "[REDACTED_AUTH]"
	PlaceholderIP    = "[REDACTED_IP]"
	PlaceholderName  = "[REDACTED_NAME]"
)

// redactor is a single compiled redaction rule. replacement may reference
// capture groups from re using the ${n} syntax (see regexp.Regexp.ReplaceAllString).
type redactor struct {
	re          *regexp.Regexp
	replacement string
}

// apply runs a sequence of redactors over s in order.
func apply(rules []redactor, s string) string {
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.replacement)
	}
	return s
}

// Scrub returns a best-effort PII-redacted copy of payload. The input is never
// mutated; a fresh slice is returned (a nil/empty input is returned unchanged).
//
// This is the primary entry point for the storage path (#9): call it on the raw
// payload bytes immediately before persistence.
func Scrub(payload []byte) []byte {
	if len(payload) == 0 {
		return payload
	}
	return []byte(ScrubString(string(payload)))
}

// ScrubString is the string-typed equivalent of Scrub. It applies every
// redaction category in a fixed order:
//
//  1. tokens/secrets — so an Authorization header or "password": "…" value is
//     masked as a whole before narrower rules (email, IP) can nibble at it;
//  2. emails;
//  3. IP addresses;
//  4. names — last, and deliberately skipping values that are already a
//     placeholder, so it never relabels e.g. an email it cannot see past a key.
func ScrubString(s string) string {
	s = RedactTokens(s)
	s = RedactEmails(s)
	s = RedactIPs(s)
	s = RedactNames(s)
	return s
}

// RedactEmails masks email addresses. Exposed for composition.
func RedactEmails(s string) string { return apply(emailRedactors, s) }

// RedactTokens masks auth tokens and secrets: Authorization/auth headers, bare
// bearer tokens, JWTs, well-known API-key/secret formats, and values assigned to
// obviously secret-named keys (password, api_key, token, …). Exposed for composition.
func RedactTokens(s string) string { return apply(tokenRedactors, s) }

// RedactIPs masks IPv4 and IPv6 addresses. Exposed for composition.
func RedactIPs(s string) string { return apply(ipRedactors, s) }

// RedactNames applies the BEST-EFFORT, deliberately weak name heuristic. See the
// nameRedactors documentation for its (significant) limitations. Exposed for composition.
func RedactNames(s string) string { return apply(nameRedactors, s) }

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

var emailRedactors = []redactor{
	// Pragmatic RFC-5321-ish address: a local part, "@", a dotted domain, and a
	// 2+ letter TLD. This intentionally does NOT match bare "@handle" mentions
	// (no local part) or "meet @ 3pm" (space around @), guarding against
	// over-redaction of social handles and prose.
	{
		re:          regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`),
		replacement: PlaceholderEmail,
	},
}

// ---------------------------------------------------------------------------
// Tokens & secrets
// ---------------------------------------------------------------------------

var tokenRedactors = []redactor{
	// Authorization / Proxy-Authorization / X-...-Authorization header values,
	// in both header form ("Authorization: Bearer <t>") and JSON form
	// ("\"authorization\": \"Bearer <t>\""). The whole credential (including any
	// scheme word) is replaced; the key and separator are preserved via ${1}.
	{
		re:          regexp.MustCompile(`(?i)((?:proxy-)?authorization\s*"?\s*[:=]\s*"?)(?:(?:bearer|basic|digest|token|negotiate)\s+)?[A-Za-z0-9._~+/=\-]+`),
		replacement: "${1}" + PlaceholderAuth,
	},
	// Standalone "Bearer <token>" not attached to an Authorization key. Requires
	// a fairly long credential so the English word "bearer" in prose (e.g.
	// "bearer of bad news") is not redacted.
	{
		re:          regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{16,}`),
		replacement: PlaceholderToken,
	},
	// JWTs, anchored on the "eyJ" header prefix (base64url of `{"`). Anchoring
	// keeps false positives near-zero: dotted identifiers such as Java package
	// names or "www.example.com" never start with eyJ and never carry base64url
	// payload/signature segments. Non-standard JWTs that do NOT start with eyJ
	// are only caught if they happen to hit one of the rules below.
	{
		re:          regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}`),
		replacement: PlaceholderToken,
	},
	// Well-known provider API-key / secret formats. These are case-sensitive by
	// design (their prefixes are fixed-case) and the random tails are restricted
	// to base62 where possible so kebab-case identifiers like the CSS class
	// "sk-loading-spinner" are not mistaken for an OpenAI "sk-" key.
	{re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}`), replacement: PlaceholderToken},                                   // GitHub tokens
	{re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`), replacement: PlaceholderToken},                                 // GitHub fine-grained PAT
	{re: regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{16,}`), replacement: PlaceholderToken},                                    // GitLab PAT
	{re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`), replacement: PlaceholderToken},                                 // Slack tokens
	{re: regexp.MustCompile(`\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}`), replacement: PlaceholderToken},                  // Stripe keys
	{re: regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9]{20,}`), replacement: PlaceholderToken},                                // OpenAI keys
	{re: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}`), replacement: PlaceholderToken},                                       // Google API key
	{re: regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}`), replacement: PlaceholderToken}, // AWS access key IDs

	// Values assigned to obviously-secret keys, in JSON ("token": "…") or
	// flag/env form (api_key=…). Key + separator (+ optional opening quote) are
	// preserved via ${1}; the value up to the next quote/space/comma/brace is
	// masked. This is the catch-all for opaque secrets that have no recognisable
	// standalone shape.
	{
		re:          regexp.MustCompile(`(?i)\b((?:passwords?|passwd|pwd|secret[_-]?key|client[_-]?secret|api[_-]?keys?|apikeys?|access[_-]?tokens?|refresh[_-]?tokens?|auth[_-]?tokens?|private[_-]?keys?|secrets?|tokens?)"?\s*[:=]\s*"?)[^"\s,}]+`),
		replacement: "${1}" + PlaceholderToken,
	},
}

// ---------------------------------------------------------------------------
// IP addresses
// ---------------------------------------------------------------------------

// IPv6 is matched before IPv4 so that an IPv4-mapped IPv6 address is masked as a
// single unit rather than leaving an "::ffff:[REDACTED_IP]" fragment.
var ipRedactors = []redactor{
	{re: regexp.MustCompile(ipv6Pattern), replacement: PlaceholderIP},
	// IPv4 with per-octet 0-255 validation, so "999.1.1.1" and 3-part semantic
	// versions ("v1.2.3") are not matched. A genuine 4-part version like
	// "1.2.3.4" is indistinguishable from an IP by regex and IS masked; this
	// ambiguity is documented as an accepted best-effort limitation.
	{re: regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b`), replacement: PlaceholderIP},
}

// ipv6Pattern is a comprehensive IPv6 matcher (RE2-safe: no back-references or
// look-around). It covers full, compressed ("::"), loopback ("::1") and
// IPv4-mapped forms. It deliberately requires either 8 groups or a "::", so
// single-colon sequences such as clock times ("12:34:56") and MAC addresses are
// not matched.
//
// Ordering matters: Go's regexp is leftmost-FIRST (Perl semantics), and this
// pattern is used unanchored for extraction, so the alternatives are ordered
// from most-consuming to least. The IPv4-embedding and multi-trailing-group
// forms come before the bare "…::" form; otherwise an address like
// "fe80::1ff:fe23:4567:890a" would match only its "fe80::" prefix.
const ipv6Pattern = `(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}` + // 1:2:3:4:5:6:7:8
	`|(?:[0-9A-Fa-f]{1,4}:){1,4}:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])` + // …::IPv4
	`|::(?:[Ff]{4}(?::0{1,4})?:)?(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])` + // ::ffff:IPv4
	`|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}` +
	`|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}` +
	`|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}` +
	`|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}` +
	`|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}` +
	`|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}` +
	`|(?:[0-9A-Fa-f]{1,4}:){1,7}:` + // 1:2:3:4:5:6:7::
	`|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:)` // ::8  /  ::

// ---------------------------------------------------------------------------
// Names (BEST-EFFORT — deliberately weak)
// ---------------------------------------------------------------------------

// nameRedactors implement a deliberately LIMITED, key-directed name heuristic.
//
// Reliable name detection is an unsolved problem, so this makes no attempt at
// it. It only masks the value that immediately follows an obvious name-ish key
// (name, full_name, first_name, last_name, display_name, username, user, …). It
// is anchored with \b so it does NOT fire on suffix collisions such as
// "filename:" or "hostname:".
//
// KNOWN, ACCEPTED LIMITATIONS (capture these in the privacy doc, #12):
//   - It MISSES every human name that appears in free-form prose, in an
//     unrecognised key, or in a nested structure it cannot parse.
//   - It OVER-redacts non-personal values that happen to sit under a name-like
//     key, e.g. `name: my-service` in a Kubernetes manifest becomes
//     `name: [REDACTED_NAME]`. This is an accepted trade-off, not a bug.
//
// Do NOT rely on this pass to remove names.
var nameRedactors = []redactor{
	// Quoted value: "name": "John Doe". The value's first character must not be
	// '[', so an existing placeholder (e.g. "[REDACTED_EMAIL]" produced by an
	// earlier pass) is left intact rather than relabelled.
	{
		re:          regexp.MustCompile(`(?i)\b((?:first[_ ]?name|last[_ ]?name|full[_ ]?name|display[_ ]?name|user[_ ]?name|nick[_ ]?name|sur[_ ]?name|username|name|user)"?\s*[:=]\s*")[^"\n\[][^"\n]{0,119}"`),
		replacement: "${1}" + PlaceholderName + `"`,
	},
	// Unquoted value: name: John Doe / user=jsmith. Consumes up to the next
	// comma, brace or line break. The first character excludes quotes, brackets,
	// braces and whitespace so quoted values (handled above), placeholders and
	// nested objects/arrays are skipped.
	{
		re:          regexp.MustCompile(`(?i)\b((?:first[_ ]?name|last[_ ]?name|full[_ ]?name|display[_ ]?name|user[_ ]?name|nick[_ ]?name|sur[_ ]?name|username|name|user)\s*[:=]\s*)[^"\s\[',}{\r\n][^,\r\n}]*`),
		replacement: "${1}" + PlaceholderName,
	},
}
