# LibreMail bug-report pipeline — data flow & privacy posture

- **Status:** Living document (reflects the design as of the date below; several stages are not yet implemented — see [Current implementation status](#current-implementation-status)).
- **Date:** 2026-07-02
- **Applies to:** the server-side debug bug-report pipeline in this repo
  (`JMR-dev/LibreMail-Bug-Report-Ingest`) and its integration with the
  [LibreMail](https://github.com/JMR-dev/LibreMail) Android app.
- **Audience:** LibreMail users, and anyone linking this from the app's README or
  F-Droid metadata ([LibreMail#16](https://github.com/JMR-dev/LibreMail/issues/16),
  [LibreMail#20](https://github.com/JMR-dev/LibreMail/issues/20)).

This document describes, end to end, what happens to a debug bug-report from the moment a
user chooses to send one, and states plainly what privacy protections exist **and where they
stop**. It is intentionally honest about limits: PII scrubbing is best-effort, not a
guarantee, and several stages below are designed but not yet built.

> **Maturity, up front.** The HTTPS ingest endpoint (`POST /v1/reports` — method and
> content-type checks, the 256 KiB size cap, v1 schema validation, and the full status-code
> contract) and the best-effort PII-scrub library are **implemented**. Encrypted-at-rest
> storage, the retention lifecycle, the manual review/removal window, and the weekly publish
> job are **specified** (in the linked decision records and tickets) but **not yet built**.
> Because the endpoint is currently wired to a no-op storage sink, accepted reports are not yet
> retained, scrubbed in-line, encrypted, or published. This document describes the *intended*
> end-to-end posture; see [Current implementation status](#current-implementation-status) for
> exactly what is live today.

---

## Privacy at a glance

*These points describe the pipeline's intended design; see
[Current implementation status](#current-implementation-status) for what is live today.*

- **Opt-in and user-initiated only.** A report is sent **only** when a user explicitly taps
  send on the app's review/submit screen. Nothing is ever collected or transmitted
  automatically or in the background.
- **You see it before it leaves.** Submission happens from a review/submit screen
  ([LibreMail#33](https://github.com/JMR-dev/LibreMail/issues/33)), so the report is
  user-visible before sending.
- **Encrypted in transit** (HTTPS/TLS to the Cloudflare edge) and **encrypted at rest**
  (AES-256-GCM; stored objects are unreadable without the maintainer-held key).
- **Best-effort PII scrubbing** removes obvious emails, tokens/secrets, and IP addresses, and
  makes a weak attempt at names — **but this is defence-in-depth, not a guarantee.** It will
  miss things and may over-redact. See [the limits](#pii-scrubbing-is-best-effort-not-a-guarantee).
- **A human is in the loop.** Reports sit encrypted and are reviewable/removable by the
  maintainer before anything is published.
- **Publication is public.** Reports that are not removed are published weekly as GitHub
  issues on the public app repo. **After publication the content is public**, so any residual
  PII the scrubber missed and the maintainer did not catch becomes public too.

---

## What a report contains

A debug bug-report is small JSON metadata (such as app/OS version and device model) plus
diagnostic text — logs, stack traces, and any free-text description the user adds. The v1
payload schema is defined by the ingest endpoint
([#7](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/7)): required `appVersion`,
`platform`, and `report`, plus optional `osVersion`, `device`, and `clientTimestamp`. Reports are capped
at **256 KiB** on ingest; realistic reports are a few KiB to low tens of KiB.

Because diagnostic text is free-form, a report **can** contain personal or sensitive data the
user did not intend to send (an email address in a log line, a token in a stack trace, a
device identifier, a name in a description). That possibility is exactly why the pipeline
combines best-effort scrubbing, encryption at rest, and a manual review window rather than
relying on any single control.

---

## End-to-end data flow

The stages below describe the *intended* end-to-end design. For which stages exist in code
today, see [Current implementation status](#current-implementation-status).

### 1. Opt-in submission (in the app)

The user triggers a debug report from the app's review/submit screen
([LibreMail#33](https://github.com/JMR-dev/LibreMail/issues/33)). This is **user-initiated
only**: there is no automatic, scheduled, or background submission path. The user is shown the
report and must actively choose to send it.

### 2. HTTPS ingest — `POST /v1/reports`

The app sends the report over **HTTPS** to the Cloudflare Worker's ingest endpoint. The
endpoint:

- accepts **`POST` only** (other methods get `405`);
- requires `Content-Type: application/json` (`415` otherwise);
- enforces a hard **256 KiB** body cap, rejecting larger bodies with `413` (checked both via
  `Content-Length` and while reading, so a missing or dishonest length cannot bypass it);
- **validates** the body against the v1 report schema — required `appVersion`, `platform`, and
  `report`, plus optional `osVersion`, `device`, and `clientTimestamp` — rejecting malformed or
  invalid input with `400`; unknown fields are ignored so newer app versions stay compatible;
- is designed to sit behind **per-IP rate limits** at the Cloudflare edge (to be provisioned via
  the Pulumi IaC, [#2](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/2)) —
  deliberately generous because mobile clients share IPs behind carrier-grade NAT. These edge
  rules are **not yet provisioned**.

On success the endpoint returns **`202 Accepted`** (the pipeline is asynchronous), or `503` if
the storage backend is unavailable. Error
responses are deliberately small and **never echo the request contents** or reveal whether a
specific IP is individually blocked, to avoid leaking data back to a caller. The concrete
size/rate/response contract is fixed in the labels-and-abuse decision record
([ADR #6](decisions/labels-and-abuse.md)).

### 3. Best-effort PII scrub

Before a report is persisted, it passes through a best-effort PII redaction pass
([`internal/scrub`](../internal/scrub/scrub.go),
[#8](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/8)). The pass **masks**
(rather than deletes) matched spans with bracketed placeholders like `[REDACTED_EMAIL]`, so
the report stays readable for triage. It targets:

- **email addresses** → `[REDACTED_EMAIL]`
- **auth tokens / secrets** → `[REDACTED_TOKEN]` / `[REDACTED_AUTH]` (Authorization headers,
  bearer tokens, JWTs, well-known provider API-key formats, and values under obviously
  secret-named keys such as `password`, `api_key`, `token`)
- **IP addresses** (IPv4 and IPv6) → `[REDACTED_IP]`
- **personal names** → `[REDACTED_NAME]` (a **deliberately weak**, key-directed heuristic)

The redaction library is implemented and unit-tested, but it is **not yet invoked on the live
ingest path**: the ingest endpoint currently hands accepted bodies to a no-op storage sink, and
scrubbing runs downstream of that seam once encrypted storage
([#9](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/9)) is wired in. Its
important **limits** are detailed in [PII scrubbing is best-effort, not a
guarantee](#pii-scrubbing-is-best-effort-not-a-guarantee) below — please read them; do not treat
a scrubbed report as certified free of PII.

### 4. Encrypted-at-rest storage in R2

The scrubbed report is encrypted **in the Worker** with **AES-256-GCM** *before* it is written
to a Cloudflare R2 bucket. Only ciphertext is ever handed to R2 — the storage service never
receives the plaintext or the key. The key is a versioned keyring held in **Cloudflare Secrets
Store**, accessible only to the maintainer. Each stored object is a self-describing encrypted
frame; GCM's authentication tag also makes objects tamper-evident. The scheme, key custody,
and rotation are specified in the encryption decision record
([ADR #5](decisions/encryption.md); storage implementation tracked in
[#9](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/9)).

The practical consequence: **a stored report is unreadable to anyone who obtains read access
to the bucket but does not hold the maintainer's key** (a leaked/over-scoped R2 token, a
misconfiguration, an accidentally public bucket, or raw at-rest disclosure yields only opaque
bytes). See [what encryption at rest does and does not
protect](#encryption-at-rest-what-it-does-and-does-not-protect).

### 5. Manual maintainer review & removal window

Stored reports are **not** published immediately. Between storage and the weekly publish run,
the maintainer can review reports and **remove** any that should not be published — for
example on a user's removal request, or on spotting residual PII the scrubber missed. Deleting
the encrypted object before the next publish run prevents it from ever becoming public. This
manual window is the last line of defence before publication and is tracked in
[#11](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/11). Retention/lifecycle
of stored objects (reports are intended to be short-lived — stored, published, then
deleted/tombstoned) is being finalised in
[#10](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/10).

### 6. Weekly publish to GitHub

Every **Friday at 17:00 America/Chicago** (US Central, DST-aware), a scheduled job decrypts
each not-yet-removed report and publishes it as a GitHub issue on the public app repo
`JMR-dev/LibreMail`. Each auto-published issue is tagged with three labels — `bug-report`,
`automated`, and `needs-triage` — so the maintainer can distinguish pipeline-originated
reports from human-filed ones (see [ADR #6](decisions/labels-and-abuse.md)). The run is capped
(oldest-first, with an alert if the cap is hit) to bound blast radius. The scheduled trigger is
tracked in [#13](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/13); the publish
job in [#14](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/14) /
[#15](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/15).

> **Publication makes content public.** A published issue lives on the public app repo. From
> that point the report's content is public and confidentiality depends entirely on what the
> scrubbing (stage 3) removed and what the maintainer caught in review (stage 5). This is why
> those two stages matter and why scrubbing's limits (below) are stated so bluntly.

---

## Privacy properties (and their limits)

### Opt-in / user-initiated only

Reports are **never** collected or sent automatically. The only way a report reaches this
pipeline is a user actively submitting one from the app's review/submit screen
([LibreMail#33](https://github.com/JMR-dev/LibreMail/issues/33)). There is no telemetry, no
background upload, and no silent collection.

### PII scrubbing is best-effort, not a guarantee

The scrub pass ([#8](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/8)) is a
good-faith, defence-in-depth layer built from regular expressions and lightweight heuristics.
**It is not a guarantee.** It *will* miss some sensitive data and it *may* over-redact
non-sensitive data that merely resembles a sensitive pattern. **No one should treat a scrubbed
report as certified free of PII.** Concretely:

- **Names are barely covered.** Name detection is a deliberately weak, key-directed heuristic:
  it only masks a value sitting immediately after an obvious name-like key (`name`,
  `full_name`, `username`, …). It **misses every name** that appears in free-form prose, under
  an unrecognised key, or in a nested structure it cannot parse — and conversely it
  **over-redacts** non-personal values that happen to sit under a name-like key (e.g.
  `name: my-service` in a config becomes `name: [REDACTED_NAME]`). Do **not** rely on this
  pass to remove names.
- **Emails must look like addresses.** Only well-formed `local@domain.tld` addresses are
  matched. Obfuscated or split forms (e.g. "john dot doe at example dot com") and other
  email-shaped strings can slip through.
- **Only recognisable secrets are caught.** Tokens are matched by well-known provider formats,
  by JWTs beginning with `eyJ`, and by values under obviously secret-named keys. An **opaque
  secret with no recognisable shape** that is not under a known key name, or a **non-standard
  JWT** that does not start with `eyJ`, can be missed.
- **Dotted-number ambiguity.** IPv4 detection cannot distinguish a real address from a
  dotted-decimal string with the same shape. A four-part software version or an OID whose
  components all fall in 0–255 (e.g. `1.2.3.4`) is **masked as an IP** — an accepted
  over-redaction trade-off. (Three-part versions like `v1.2.3` are not matched.)
- **General.** The pass masks rather than deletes, is idempotent, and is schema-agnostic; but
  by construction it is pattern-based and therefore incomplete.

These are accepted limitations, documented in the package itself
([`internal/scrub/scrub.go`](../internal/scrub/scrub.go)). Encryption at rest (stage 4) and
the manual review window (stage 5) exist precisely because scrubbing is not sufficient on its
own — and because any residual PII becomes public once an issue is published.

### Encryption at rest — what it does and does not protect

Encryption at rest ([ADR #5](decisions/encryption.md)) means stored reports are **opaque
ciphertext**: unreadable without the maintainer-held key in Cloudflare Secrets Store, and
tamper-evident via AES-GCM's authentication tag.

**It defends against:** a leaked or over-scoped R2 token, a bucket misconfiguration, an
accidentally public bucket, raw at-rest/backup disclosure, and object tampering or
substitution. In all of these an attacker with bucket access but no key gets nothing usable.

**It does not defend against** (stated so this is not overclaimed):

- **A fully compromised Cloudflare platform.** The Worker's compute runs on Cloudflare and the
  key is held in Cloudflare Secrets Store, so Cloudflare-the-platform is necessarily trusted
  with plaintext at processing time. Defending against the compute provider itself is out of
  scope by design.
- **The published GitHub issues.** Post-publication confidentiality is a *separate* concern,
  governed by scrubbing quality and repo visibility (see stage 6) — not by at-rest encryption.
- **Loss of the key.** The flip side of "unreadable without the key" is that losing the key
  means the not-yet-published reports are permanently unrecoverable (mitigated by an offline
  keyring backup).

---

## Current implementation status

A concise, honest snapshot so this document does not overstate what runs today. This section is
the single source of truth for status; the flow above describes the *intended* design.

**Implemented in this repo:** the service bootstrap and health endpoints
([#1](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/1)); continuous integration
([#3](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/3)); the Pulumi
infrastructure-as-code that provisions the Worker, the R2 bucket, and DNS
([#2](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/2)); the HTTPS ingest
endpoint `POST /v1/reports` with its 256 KiB cap, v1 schema validation, and full status-code
contract ([#7](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/7)); and the
best-effort PII-scrub library
([#8](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/8)).

**Not yet implemented:** encrypted-at-rest R2 storage logic
([#9](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/9)); object
retention/lifecycle ([#10](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/10));
the manual review/removal window
([#11](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/11)); the scheduled trigger
([#13](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/13)); the weekly publish
job ([#14](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/14) /
[#15](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/15)); and the edge
rate-limiting ruleset (designed in [ADR #6](decisions/labels-and-abuse.md), reserved in the IaC
but not yet provisioned).

**What this means today:** the ingest endpoint validates and accepts reports but is wired to a
no-op storage sink, so accepted reports are **not** currently retained, scrubbed in-line,
encrypted, or published. The scrub library exists and is unit-tested but is not yet invoked on
the live request path — it runs downstream of the storage seam, which lands with #9. This
section is updated as stages land.

---

## References

- [ADR #5 — Encryption scheme & key custody for R2 objects](decisions/encryption.md)
- [ADR #6 — GitHub labels + ingest abuse / rate-limit policy](decisions/labels-and-abuse.md)
- [`internal/ingest`](../internal/ingest/) — the `POST /v1/reports` endpoint, v1 schema, and
  response contract
- [`internal/scrub/scrub.go`](../internal/scrub/scrub.go) — the best-effort redaction pass and
  its documented limitations
- Project [README](../README.md) — overview and repository layout
- Parent tracking issue: [JMR-dev/LibreMail#11](https://github.com/JMR-dev/LibreMail/issues/11)
