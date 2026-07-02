package scrub

import (
	"bytes"
	"strings"
	"testing"
)

// redactedOK asserts that got differs from in, contains the expected
// placeholder, and no longer contains any of the sensitive substrings.
func redactedOK(t *testing.T, got, in, placeholder string, secrets ...string) {
	t.Helper()
	if got == in {
		t.Errorf("expected redaction but output was unchanged: %q", in)
	}
	if !strings.Contains(got, placeholder) {
		t.Errorf("output %q is missing placeholder %q", got, placeholder)
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(got, s) {
			t.Errorf("output %q still leaks sensitive substring %q", got, s)
		}
	}
}

// unchanged asserts that a supposedly-safe input is passed through verbatim
// (guards against over-redaction).
func unchanged(t *testing.T, got, in string) {
	t.Helper()
	if got != in {
		t.Errorf("expected no change (over-redaction guard):\n in  = %q\n got = %q", in, got)
	}
}

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

func TestRedactEmails(t *testing.T) {
	redact := []struct {
		name, in, secret string
	}{
		{"simple", `contact me at alice@example.com please`, "alice@example.com"},
		{"plus tag and subdomain", `from john.doe+tag@mail.sub.example.co.uk`, "john.doe+tag@mail.sub.example.co.uk"},
		{"uppercase", `ALICE@EXAMPLE.COM`, "ALICE@EXAMPLE.COM"},
		{"digits and dashes", `user-123.name@my-host.io`, "user-123.name@my-host.io"},
		{"inside json", `{"reporter":"bob@example.org"}`, "bob@example.org"},
		{"inside angle brackets", `Bob <bob@example.org>`, "bob@example.org"},
	}
	for _, tc := range redact {
		t.Run("redact/"+tc.name, func(t *testing.T) {
			redactedOK(t, RedactEmails(tc.in), tc.in, PlaceholderEmail, tc.secret)
		})
	}

	keep := []struct {
		name, in string
	}{
		{"social handle", `follow @acmecorp for updates`},
		{"cc mention", `ping @channel now`},
		{"meet at time", `let's meet @ 3pm tomorrow`},
		{"java annotation", `@Override public void run()`},
		{"local only no tld", `login as user@localhost works`},
		{"at with no domain", `rate is 5@each item`},
	}
	for _, tc := range keep {
		t.Run("keep/"+tc.name, func(t *testing.T) {
			unchanged(t, RedactEmails(tc.in), tc.in)
		})
	}
}

// ---------------------------------------------------------------------------
// Tokens & secrets
// ---------------------------------------------------------------------------

func TestRedactTokens(t *testing.T) {
	jwt := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`

	// gitlabPAT is assembled at runtime rather than written as a literal: the
	// GitLab token pattern has no checksum, so secret scanners flag any
	// contiguous "glpat-<20 chars>" string on sight — even obvious test data.
	// Concatenation keeps the literal out of the source blob while still
	// producing a value that exercises the redaction regex.
	gitlabPAT := "glpat-" + strings.Repeat("A", 20)

	redact := []struct {
		name, in, placeholder, secret string
	}{
		// Authorization headers (header + JSON forms, several schemes).
		{"auth header bearer", `Authorization: Bearer ` + jwt, PlaceholderAuth, jwt},
		{"auth header basic", `Authorization: Basic dXNlcjpwYXNzd29yZA==`, PlaceholderAuth, "dXNlcjpwYXNzd29yZA=="},
		{"auth header json", `"authorization": "Bearer abc.def.ghijklmnop"`, PlaceholderAuth, "abc.def.ghijklmnop"},
		{"proxy auth header", `Proxy-Authorization: Bearer sometokenvalue1234`, PlaceholderAuth, "sometokenvalue1234"},
		// Standalone bearer.
		{"bearer standalone", `sent header Bearer 0123456789abcdefghij done`, PlaceholderToken, "0123456789abcdefghij"},
		// JWT anchored on eyJ.
		{"jwt bare", `id_token=` + jwt, PlaceholderToken, jwt},
		// Well-known provider key formats.
		{"github token", `token ghp_0123456789abcdefghijklmnopqrstuvwxyz`, PlaceholderToken, "ghp_0123456789abcdefghijklmnopqrstuvwxyz"},
		{"github pat", `github_pat_11ABCDEFG0aBcDeFgHiJkL_mNoPqRsTuVwXyZ012345`, PlaceholderToken, "github_pat_11ABCDEFG0aBcDeFgHiJkL_mNoPqRsTuVwXyZ012345"},
		{"gitlab pat", gitlabPAT, PlaceholderToken, gitlabPAT},
		{"slack token", `xoxb-1234567890-abcdefghijkl`, PlaceholderToken, "xoxb-1234567890-abcdefghijkl"},
		{"stripe secret key", `sk_live_0123456789abcdefABCDEF`, PlaceholderToken, "sk_live_0123456789abcdefABCDEF"},
		{"openai key", `sk-abcdefghijklmnopqrstuvwxyz0123`, PlaceholderToken, "sk-abcdefghijklmnopqrstuvwxyz0123"},
		{"google api key", `AIzaSyA0123456789abcdefghijklmnopqrstuv`, PlaceholderToken, "AIzaSyA0123456789abcdefghijklmnopqrstuv"},
		{"aws access key id", `AKIAIOSFODNN7EXAMPLE`, PlaceholderToken, "AKIAIOSFODNN7EXAMPLE"},
		// Secret-named key assignments (JSON / env / header forms).
		{"password json", `{"password": "hunter2!"}`, PlaceholderToken, "hunter2!"},
		{"api_key env", `api_key=super-secret-value-42`, PlaceholderToken, "super-secret-value-42"},
		{"access_token colon", `access_token: aQ9xZ_opaquevalue`, PlaceholderToken, "aQ9xZ_opaquevalue"},
		{"client secret", `client_secret = 0f1e2d3c4b5a`, PlaceholderToken, "0f1e2d3c4b5a"},
		{"x-auth-token header", `X-Auth-Token: s3cr3tvalue123`, PlaceholderToken, "s3cr3tvalue123"},
		{"private key kv", `"private_key":"MIIBVerySecretMaterial"`, PlaceholderToken, "MIIBVerySecretMaterial"},
	}
	for _, tc := range redact {
		t.Run("redact/"+tc.name, func(t *testing.T) {
			redactedOK(t, RedactTokens(tc.in), tc.in, tc.placeholder, tc.secret)
		})
	}

	keep := []struct {
		name, in string
	}{
		{"bearer in prose", `he was the bearer of bad news`},
		{"css sk prefix", `class="sk-loading-spinner-container-large"`},
		{"short aws-like", `AKIASHORT is not a key`},
		{"jwt-like domain", `visit www.example.com and analytics.google.com`},
		{"java package", `at com.example.myapp.service.Handler.run(Handler.java:42)`},
		{"secret word in prose", `there is nothing secret here at all`},
		{"semver token-ish", `upgraded to version 1.2.3 today`},
	}
	for _, tc := range keep {
		t.Run("keep/"+tc.name, func(t *testing.T) {
			unchanged(t, RedactTokens(tc.in), tc.in)
		})
	}
}

// ---------------------------------------------------------------------------
// IP addresses
// ---------------------------------------------------------------------------

func TestRedactIPs(t *testing.T) {
	redact := []struct {
		name, in, secret string
	}{
		// IPv4
		{"ipv4 private", `client 192.168.0.42 connected`, "192.168.0.42"},
		{"ipv4 public", `resolved to 8.8.8.8`, "8.8.8.8"},
		{"ipv4 broadcast bound", `mask 255.255.255.255 here`, "255.255.255.255"},
		{"ipv4 zero", `bound 0.0.0.0:8080`, "0.0.0.0"},
		{"ipv4 in json", `{"ip":"10.0.0.1"}`, "10.0.0.1"},
		// IPv6
		{"ipv6 full", `addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334 up`, "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		{"ipv6 compressed", `peer 2001:db8::8a2e:370:7334 seen`, "2001:db8::8a2e:370:7334"},
		{"ipv6 loopback", `bind ::1 only`, "::1"},
		{"ipv6 link local", `via fe80::1ff:fe23:4567:890a here`, "fe80::1ff:fe23:4567:890a"},
		{"ipv6 trailing colons", `route 1:2:3:4:5:6:7:: set`, "1:2:3:4:5:6:7::"},
		{"ipv6 mapped ipv4", `mapped ::ffff:192.168.1.1 shown`, "::ffff:192.168.1.1"},
	}
	for _, tc := range redact {
		t.Run("redact/"+tc.name, func(t *testing.T) {
			redactedOK(t, RedactIPs(tc.in), tc.in, PlaceholderIP, tc.secret)
		})
	}

	keep := []struct {
		name, in string
	}{
		{"clock time", `event at 12:34:56 today`},
		{"clock time ms", `stamp 12:00:00 exactly`},
		{"mac address", `nic 00:1A:2B:3C:4D:5E present`},
		{"semver three part", `running v1.2.3 build`},
		{"octet over 255", `not an ip 999.1.1.1 here`},
		{"octet 256", `bad 256.100.100.100 value`},
		{"key value colon", `config foo:bar baz:qux`},
	}
	for _, tc := range keep {
		t.Run("keep/"+tc.name, func(t *testing.T) {
			unchanged(t, RedactIPs(tc.in), tc.in)
		})
	}
}

// ---------------------------------------------------------------------------
// Names (best-effort)
// ---------------------------------------------------------------------------

func TestRedactNames(t *testing.T) {
	redact := []struct {
		name, in, secret string
	}{
		{"json name", `{"name": "John Doe"}`, "John Doe"},
		{"unquoted name", `name: Jane Roe`, "Jane Roe"},
		{"username", `username: jsmith`, "jsmith"},
		{"user", `user=administrator`, "administrator"},
		{"first name camel", `"firstName": "Grace"`, "Grace"},
		{"last name snake", `last_name: Hopper`, "Hopper"},
		{"full name", `"full_name":"Ada Lovelace"`, "Ada Lovelace"},
		{"display name", `display_name: coolcat99`, "coolcat99"},
		{"nickname", `nickname: Ace`, "Ace"},
	}
	for _, tc := range redact {
		t.Run("redact/"+tc.name, func(t *testing.T) {
			redactedOK(t, RedactNames(tc.in), tc.in, PlaceholderName, tc.secret)
		})
	}

	keep := []struct {
		name, in string
	}{
		// Suffix collisions must NOT trigger the bare "name" key.
		{"filename", `filename: report.pdf`},
		{"hostname", `hostname: web01.internal`},
		{"codename", `codename: falcon`},
		{"pathname", `pathname: /var/log/app`},
		{"user-agent header", `user-agent: Mozilla/5.0`},
		{"user_id key", `user_id: 12345`},
		// Best-effort limitation: names in free-form prose are NOT detected.
		{"name in prose", `my name is Robert and I like tea`},
	}
	for _, tc := range keep {
		t.Run("keep/"+tc.name, func(t *testing.T) {
			unchanged(t, RedactNames(tc.in), tc.in)
		})
	}
}

// ---------------------------------------------------------------------------
// Structure preservation (exact output)
// ---------------------------------------------------------------------------

// TestExactOutput locks the exact, structure-preserving replacements for a
// representative case per category, proving redaction masks rather than deletes.
func TestExactOutput(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"email", `email=alice@example.com;`, `email=` + PlaceholderEmail + `;`},
		{"auth header", `Authorization: Bearer abcdef.ghijk.lmnop`, `Authorization: ` + PlaceholderAuth},
		{"password json", `{"password": "hunter2"}`, `{"password": "` + PlaceholderToken + `"}`},
		{"ipv4", `[10.1.2.3]`, `[` + PlaceholderIP + `]`},
		{"ipv6 loopback", `(::1)`, `(` + PlaceholderIP + `)`},
		{"name json", `{"name": "John Doe"}`, `{"name": "` + PlaceholderName + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ScrubString(tc.in); got != tc.want {
				t.Errorf("ScrubString(%q)\n got  = %q\n want = %q", tc.in, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Integration, API surface, idempotency, immutability
// ---------------------------------------------------------------------------

const sampleReport = `Bug report:
User contact: alice@example.com, backup bob@work.co.uk
Session: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlX3ZhbHVl
Config: {"api_key": "sk_live_abcd1234efgh5678ijkl", "name": "Carol Smith"}
Env: AWS_KEY=AKIAIOSFODNN7EXAMPLE password=p@ssw0rd!
Network: connected from 203.0.113.7 via gateway 2001:db8::1
Stack: at com.example.app.Main.run(Main.java:99)`

func TestScrubStringIntegration(t *testing.T) {
	got := ScrubString(sampleReport)

	mustBeGone := []string{
		"alice@example.com", "bob@work.co.uk",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlX3ZhbHVl",
		"sk_live_abcd1234efgh5678ijkl", "Carol Smith",
		"AKIAIOSFODNN7EXAMPLE", "p@ssw0rd!",
		"203.0.113.7", "2001:db8::1",
	}
	for _, s := range mustBeGone {
		if strings.Contains(got, s) {
			t.Errorf("integration: output still leaks %q\nfull output:\n%s", s, got)
		}
	}

	// Non-sensitive structure must survive (guard against over-redaction of the
	// surrounding stack trace / labels).
	for _, s := range []string{"Bug report:", "com.example.app.Main.run", "Main.java:99"} {
		if !strings.Contains(got, s) {
			t.Errorf("integration: expected non-sensitive text %q to survive\nfull output:\n%s", s, got)
		}
	}

	for _, p := range []string{PlaceholderEmail, PlaceholderAuth, PlaceholderToken, PlaceholderIP, PlaceholderName} {
		if !strings.Contains(got, p) {
			t.Errorf("integration: expected placeholder %q in output\nfull output:\n%s", p, got)
		}
	}
}

func TestScrubIdempotent(t *testing.T) {
	once := ScrubString(sampleReport)
	twice := ScrubString(once)
	if once != twice {
		t.Errorf("scrub is not idempotent:\n once  = %q\n twice = %q", once, twice)
	}
}

func TestScrubBytes(t *testing.T) {
	in := []byte(`ip 10.0.0.1 mail x@y.io`)
	original := append([]byte(nil), in...) // snapshot

	got := Scrub(in)

	if bytes.Contains(got, []byte("10.0.0.1")) || bytes.Contains(got, []byte("x@y.io")) {
		t.Errorf("Scrub did not redact: %q", got)
	}
	if !bytes.Equal(in, original) {
		t.Errorf("Scrub mutated its input: before=%q after=%q", original, in)
	}
}

func TestScrubBytesNilAndEmpty(t *testing.T) {
	if got := Scrub(nil); got != nil {
		t.Errorf("Scrub(nil) = %q, want nil", got)
	}
	if got := Scrub([]byte{}); len(got) != 0 {
		t.Errorf("Scrub(empty) = %q, want empty", got)
	}
}

func TestScrubStringNoSecretsUnchanged(t *testing.T) {
	// A payload with nothing sensitive must pass through untouched.
	in := `Steps to reproduce: open the app, click Settings, observe crash. Build 4.7 on Android 14.`
	if got := ScrubString(in); got != in {
		t.Errorf("clean payload changed:\n in  = %q\n got = %q", in, got)
	}
}
