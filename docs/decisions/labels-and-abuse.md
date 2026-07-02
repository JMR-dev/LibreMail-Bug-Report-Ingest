# ADR: GitHub labels + ingest abuse / rate-limit policy

- **Status:** Proposed (becomes Accepted on merge)
- **Date:** 2026-07-02
- **Ticket:** [#6](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/6)
- **Unblocks:** [#14](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/14) (publish job) - **Informs:** [#7](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/7) (ingest endpoint)
- **Parent:** [JMR-dev/LibreMail#11](https://github.com/JMR-dev/LibreMail/issues/11) open question: "Target GitHub label(s); abuse / rate limiting."

## Context

A Cloudflare Worker (Go) exposes an HTTPS ingest endpoint that accepts user-initiated,
opt-in debug bug-report POSTs from the LibreMail Android app. Accepted reports are
best-effort scrubbed of PII, stored encrypted in Cloudflare R2, and every Friday at 17:00
Central a scheduled job publishes any not-manually-removed report as a GitHub issue on the
app repo `JMR-dev/LibreMail`.

Constraints that shape this decision:

- **Single maintainer, low expected volume.** Reports are user-initiated debug submissions
  only; realistic legitimate volume is single digits per week.
- **Mobile clients behind CGNAT.** Many distinct users share a small pool of public IPs via
  carrier-grade NAT, so per-IP limits must be generous enough not to lock out a whole carrier.
- **IaC is Pulumi (Go).** Infrastructure (including edge rate-limit rules) is provisioned
  declaratively, which favours a config-driven rate-limit mechanism over hand-rolled state.
- **Existing labels on `JMR-dev/LibreMail`** (checked 2026-07-02): `bug`, `documentation`,
  `duplicate`, `enhancement`, `good first issue`, `help wanted`, `invalid`, `question`,
  `wontfix`, `Infrastructure`, `Compliance`, `Release`, `donotmerge`. There is **no**
  `bug-report`, `needs-triage`, or `automated` label yet, and the generic `bug` label is
  reserved for maintainer-confirmed defects, so a distinct marker is needed.

This ADR fixes concrete values so #7 and #14 can be implemented without further decisions.
It **decides** the labels; it does **not** create them (that is #14's implementation job).

---

## Decision 1 - GitHub labels on auto-published issues

Every issue created by the weekly publish job on `JMR-dev/LibreMail` is tagged with **all
three** labels below. Names are lowercase kebab-case (consistent with GitHub's built-in
`bug` / `good first issue` style and trivially queryable).

| Label          | Suggested colour | Applied      | Meaning                                                                                          | Removed by |
| -------------- | ---------------- | ------------ | ------------------------------------------------------------------------------------------------ | ---------- |
| `bug-report`   | `#e99695`        | at creation  | This issue originated from the app's opt-in debug bug-report ingest pipeline. Distinct from the maintainer-triaged `bug` label. Permanent origin marker. | never (permanent) |
| `automated`    | `#c5def5`        | at creation  | Provenance: the issue was created by the weekly publish job, not written by a human. Lets the maintainer filter/automate bot-created issues. | never (permanent) |
| `needs-triage` | `#fbca04`        | at creation  | Workflow state: the report has not yet been reviewed/confirmed by the maintainer.                | maintainer, once triaged |

**Rationale for three labels:** `bug-report` + `automated` are permanent provenance markers
(origin and authorship); `needs-triage` is a mutable workflow state the maintainer clears.
Together they give a clean triage inbox query:

```
repo:JMR-dev/LibreMail is:issue is:open label:bug-report label:needs-triage
```

**Requirement for #14:** before (or while) creating issues, the publish job **must ensure
each label exists on `JMR-dev/LibreMail`, creating any that are missing** (idempotent
create-or-ignore via the GitHub Labels API). None of the three exist today. Suggested
colours above are non-binding; the maintainer may recolour without changing this ADR.
Label **names** are binding (they are the contract between #14's creation step and its
application step, and any maintainer saved queries).

---

## Decision 2 - Ingest endpoint abuse / rate-limit policy (for #7)

### 2.1 Maximum request / payload size

- **Hard limit: 256 KiB (262,144 bytes) for the request body.** Requests larger than this
  are rejected with **413**.
- **Enforce in two places** (do not trust a single signal):
  1. Fast path: if `Content-Length` is present and exceeds the limit, reject with 413
     **before** reading the body.
  2. Hard cap while reading: wrap the body reader so it stops and returns 413 once
     262,144 bytes have been read (covers missing/chunked/lying `Content-Length` and
     protects against memory exhaustion).

**Justification:** A debug report is JSON metadata (app/OS version, device model) plus logs
and stack traces. Realistic reports are a few KiB to low tens of KiB. 256 KiB leaves
generous headroom (~250k characters, thousands of log lines) while being far too small to be
useful as an abuse/exfiltration vector or to bloat R2. **Note for #14:** GitHub issue bodies
are capped at **65,536 characters**, so #14 must truncate or attach when formatting a report
whose rendered body would exceed that; the 256 KiB ingest cap is intentionally larger than
the GitHub cap and is not the same limit.

### 2.2 Rate limit per client IP

| Rule            | Threshold                              | Action                                | Purpose                              |
| --------------- | -------------------------------------- | ------------------------------------- | ------------------------------------ |
| Burst           | > 15 requests / 60 s per IP            | 429; block that IP for 10 minutes     | Stop a script hammering the endpoint |
| Sustained       | > 100 requests / 1 h per IP            | 429; block that IP for 1 hour         | Catch slower, sustained abuse        |
| Global (optional, defense-in-depth) | > 1,000 accepted reports / 1 h across all IPs | 503 + alert the maintainer | Distributed abuse bypassing per-IP limits |

**Justification for the (generous) per-IP numbers:** a legitimate user submits once, maybe
retrying a few times. 15/min and 100/hr are far above that, deliberately, because CGNAT means
many real users can share one public IP; tighter limits risk blocking a whole mobile carrier.
A malicious client still does thousands/min, so 15/min blocks abuse decisively. Numbers are
starting points; the maintainer should tighten if abuse appears (see Consequences).

### 2.3 Mechanism

**Recommended (primary): Cloudflare Rate Limiting rules, provisioned via Pulumi.**

- Runs at the edge **before** the Worker executes: rejected requests cost no Worker
  invocation/CPU and never touch application code - strong volumetric protection, cheaply.
- Declarative, so it lives in the existing Pulumi (Go) IaC alongside the rest of the infra;
  no custom counter state to write or maintain.
- **Trade-offs:** requires the Rate Limiting rules feature on the account's Cloudflare plan;
  counting is IP-based and therefore coarse under CGNAT (accepted, per 2.2).

**Alternatives (documented, not chosen for v1):**

- *Workers Rate Limiting binding* (`env.RATE_LIMITER.limit({ key })`) - in-Worker, use if
  edge Rate Limiting rules are unavailable on the plan. Runs inside the Worker (costs an
  invocation) but needs no external store.
- *Durable Object token bucket* - strongly consistent, supports custom keys (e.g. per
  app-supplied token rather than IP). Most accurate but adds a DO round-trip, DO cost, and
  code complexity. **Not** justified for this low-volume, single-maintainer project up front;
  revisit only if per-IP rules prove inadequate.
- *Workers KV counter* - **rejected**: KV is eventually consistent, so counts undercount
  across edge locations, making it unreliable for enforcing a rate limit.

Regardless of the rate-limit mechanism, the **Worker always enforces the size cap (2.1) and
schema validation (2.4)** itself - those cannot be expressed as an edge rate rule.

### 2.4 Response-code contract

| Status                        | When                                                                                     | Notes / headers                                                    |
| ----------------------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| **202 Accepted**              | Well-formed report accepted, scrubbed, and stored for the weekly publish run             | Body `{"status":"accepted"}`. Async pipeline, so 202 (not 200).   |
| **400 Bad Request**           | Not valid JSON, missing/invalid required fields, or fails schema validation              | Body `{"error":"<generic reason>"}`. Never echo request contents. |
| **413 Payload Too Large**     | Body exceeds 256 KiB (per 2.1)                                                            | -                                                                 |
| **415 Unsupported Media Type**| `Content-Type` is not `application/json` (may be folded into 400 if #7 prefers)           | -                                                                 |
| **405 Method Not Allowed**    | Any method other than POST                                                                | Send `Allow: POST`.                                               |
| **429 Too Many Requests**     | Rate limit exceeded (per 2.2)                                                             | **Must** send `Retry-After: <seconds>`.                           |
| **500 Internal Server Error** | Unexpected server error                                                                   | Generic body; log internally.                                     |
| **503 Service Unavailable**   | Storage (R2) unavailable, or global shed (2.2)                                            | May send `Retry-After`.                                           |

**Client retry contract** (the app honours this):

- **429** - wait for `Retry-After`, then retry.
- **5xx** - retry with exponential backoff + jitter, bounded attempts.
- **400 / 413 / 415** - permanent; do **not** retry (the request is malformed/too large).

Error responses must be small and must not reflect request contents or reveal whether a
specific IP is individually blocked (avoid info leak / log injection).

---

## Decision 3 - Weekly publish job policy (for #14)

### 3.1 Per-run issue cap

- **Maximum 50 issues created per weekly run.** If more than 50 reports are pending, publish
  the **oldest 50**, leave the remainder pending for the next run, and **alert the
  maintainer** that the cap was hit.

**Justification:** 50 is far above realistic legitimate weekly volume, so it never throttles
normal flow, but it caps blast radius if abuse slips through or a bug produces a surge -
better to throttle and alert than to flood the app repo with hundreds of auto-issues. Draining
oldest-first over subsequent runs is the safer failure mode; the maintainer can raise the cap
or purge abusive reports.

### 3.2 GitHub API pacing, backoff, and retry

GitHub's authenticated **primary** limit is 5,000 requests/hour; **secondary** limits cap
content creation (guidance: serial requests, ~1 s between mutations, and roughly 80
content-creating requests/min / 500/hour). The policy below sits comfortably under all of
these (50 issues at 1 s spacing is ~50 s of wall-clock; awaiting network I/O does not consume
Worker CPU time, so it fits within the scheduled-event budget).

- **Serialize** issue creation - one at a time, **no concurrency**.
- **Space successful creates by at least 1 second.**
- **Honour `Retry-After` exactly** whenever a 403/429 response includes it (overrides the
  computed backoff below).
- **On 403/429 with `x-ratelimit-remaining: 0`** - wait until the `x-ratelimit-reset` epoch,
  then retry.
- **On a secondary-rate-limit 403 without `Retry-After`** - wait a **minimum of 60 s**, then
  apply the exponential schedule below.
- **On 5xx / network errors** - exponential backoff `min(60s, 1s * 2^attempt)` with **full
  jitter**, **max 5 attempts per issue**. Schedule: ~1s, 2s, 4s, 8s, 16s (capped at 60s),
  each jittered.
- **On attempt exhaustion** - leave that report **pending** (do not mark published), log +
  alert, and continue with the next report. Never abort the whole run for one failure.
- **Idempotency / de-dup** - a report is marked published **only after a confirmed 201
  Created**. On an ambiguous failure (e.g. timeout after POST) the report stays pending and
  #14's own de-dup mechanism (a stored per-report published marker / issue URL) must prevent a
  duplicate on the next run. (Detailed de-dup design is #14's scope; this ADR only fixes the
  "mark published only on confirmed success" rule.)

---

## Consequences

**Positive**

- #7 and #14 have concrete, implementable numbers with no open decisions.
- Edge rate limiting (Cloudflare rules via Pulumi) protects the Worker cheaply and fits the
  existing IaC; the Worker still owns size + schema validation.
- Three provenance/state labels give the maintainer a clean, queryable triage inbox and keep
  auto-reports distinct from the human-triaged `bug` label.
- The per-run cap + backoff make the publish job safe against surges and GitHub secondary
  limits, and safe to re-run (de-dup, mark-on-confirm).

**Negative / limitations**

- IP-based rate limiting is coarse under mobile CGNAT: shared IPs mean the per-IP limits are
  deliberately loose, and a burst from one carrier could still occasionally throttle a real
  user. Mitigated by generous thresholds + short block durations; revisit with per-app-token
  limits (Durable Object) if needed.
- The 256 KiB ingest cap (and the downstream 65,536-char GitHub issue-body cap) may truncate
  extremely verbose reports. Acceptable for a debug pipeline; #14 truncates/attaches.
- The 50/run cap means a large legitimate backlog would drain over several weeks. Acceptable
  and safer than flooding; the maintainer is alerted when the cap is hit.

**Follow-ups**

- Revisit all thresholds after observing real traffic.
- Consider an app-supplied shared secret / attestation on the ingest request to reduce
  anonymous abuse (feeds #7), and a Durable Object token bucket if IP limits prove inadequate.

## Values the maintainer should confirm at review

- **Three labels** (`bug-report`, `automated`, `needs-triage`) vs. a leaner set - is
  `needs-triage` wanted at creation, or should it be applied manually?
- **256 KiB** payload cap.
- **Per-IP limits** (15/min, 100/hr) and whether the optional global 1,000/hr shed is wanted
  in v1.
- **50 issues/run** cap and where the "cap hit" alert should go.
