# ADR 0003: Authentication for the maintainer admin API

- **Status:** Accepted
- **Date:** 2026-07-02
- **Deciders:** Maintainer (single-maintainer project)
- **Ticket:** [#11](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/11) — Manual review/removal path for maintainers
- **Depends on:** [#10](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/10) (report lifecycle: `MarkRemoved`)
- **Related:** [#13](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/13) (weekly publish reads `ListPending`; a removed report is excluded)

---

## Context

The weekly job publishes every still-pending report as a GitHub issue. Before that
run the single maintainer needs an authenticated way to (a) list the pending
reports and (b) remove a specific one so it is never published. This adds two
admin endpoints to the existing Worker HTTP handler:

```
GET    /v1/admin/reports              -> 200 {"status":"ok","reports":[<id>...]}
POST   /v1/admin/reports/{id}/remove  -> 200 {"status":"removed","id":<id>}
DELETE /v1/admin/reports/{id}         -> 200 (REST alias of the POST above)
```

`remove` calls `lifecycle.Manager.MarkRemoved` (#10), transitioning the report
`pending -> removed`; #13's `ListPending` then no longer returns it, so it is
excluded from the next publish run. These endpoints are destructive and expose
report ids, so they must be authenticated. The endpoints run in a Cloudflare
Worker (Go/TinyGo/Wasm) with secrets in Cloudflare Secrets Store.

## Decision

**Authenticate with a shared-secret Bearer token**, compared in constant time.

- Every admin request must send `Authorization: Bearer <token>`.
- The presented token is compared to the configured secret with
  `crypto/subtle.ConstantTimeCompare`, so a wrong guess leaks no timing signal.
- The scheme (`Bearer`) is matched case-insensitively per RFC 7235; anything else
  (missing header, wrong scheme, wrong token) returns **401** with a
  `WWW-Authenticate: Bearer` challenge. A wrong method on an admin path returns
  **405**; an unknown/never-pending id returns **404**.
- **Fail closed:** if the server has no secret configured (unset or empty), every
  admin request is rejected with 401 regardless of what the client sends. A
  missing secret binding can therefore never silently disable authentication.
- **Secret custody:** in production the secret is the Cloudflare Secrets Store
  binding `ADMIN_TOKEN` (wrangler.jsonc `secrets_store_secrets`), read per request
  (like the encryption keyring in ADR #5) and never logged or echoed. The dev
  server and tests inject the token directly (env var `ADMIN_TOKEN` for the dev
  server), so the exact same handler is exercised locally.

## Alternatives considered

- **Cloudflare Access (Zero Trust) in front of the route.** Strong (SSO, device
  posture, short-lived JWTs, per-request audit) and requires no app-side secret.
  **Rejected for v1:** it needs a Zero Trust org, an application, and an access
  policy to be provisioned and maintained, and it complicates scripted/`curl`/CI
  access — disproportionate for a single maintainer removing the occasional
  report. It remains the natural upgrade if the maintainer set grows or richer
  audit is wanted; it can be layered in front of the Bearer check later without
  changing the handler.
- **mTLS / client certificates.** Operationally heavy (cert issuance, rotation,
  client provisioning) for one operator. Rejected.
- **No dedicated auth, rely on an unguessable URL.** Rejected: not real
  authentication, leaks via logs/history, and cannot be rotated cleanly.

## Consequences

- **Positive:** minimal moving parts; one secret to rotate (rotate the Secrets
  Store value); trivially callable from `curl`, scripts, or CI; the auth is plain,
  build-tag-free Go that is fully host-testable (`httptest`) and exercised end to
  end by the Bruno API tests against the dev server.
- **Negative / limitations:** a single shared secret has no per-user identity or
  built-in audit trail, and if leaked it grants full admin until rotated. Mitigated
  by constant-time comparison, fail-closed behaviour, never logging the token, and
  HTTPS-only transport (the Worker is HTTPS). Revisit with Cloudflare Access if the
  maintainer set grows or per-actor audit becomes a requirement.
