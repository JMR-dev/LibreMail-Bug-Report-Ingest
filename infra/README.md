# Infrastructure (Pulumi, Go)

Infrastructure-as-code for the LibreMail bug-report ingest pipeline. This is its
own Go module (`github.com/JMR-dev/LibreMail-Bug-Report-Ingest/infra`) so the
Worker module at the repo root stays lean.

It provisions, with the Pulumi Go SDK and the
[`pulumi-cloudflare`](https://www.pulumi.com/registry/packages/cloudflare/) and
[`pulumi-gcp`](https://www.pulumi.com/registry/packages/gcp/) providers:

| Resource | Type | Purpose |
| --- | --- | --- |
| `ingest-worker` | `cloudflare.WorkersScript` | The ingest Worker (`libremail-bug-report-ingest`, built in #1), wired with its full binding set (R2 + Secrets Store + vars, see [Worker bindings](#worker-bindings)). |
| `reports-bucket` | `cloudflare.R2Bucket` | Encrypted bug-report storage (`libremail-bug-reports`). Per [ADR 0001](../docs/decisions/encryption.md) only ciphertext is written. |
| `ingest-cron-triggers` | `cloudflare.WorkersCronTrigger` | The two Friday UTC Cron Triggers (#13) that drive the weekly publish job; bound to the ingest Worker. |
| `ingest-dns-record` | `gcp.dns.RecordSet` | Google Cloud DNS record pointing the ingest hostname at the Worker's route/custom domain. |

DNS authority is **Google Cloud DNS**. The managed zone is **referenced by name**
(it already exists / is managed elsewhere), and this stack only adds a record to
it.

> **Worker content: placeholder by default, real artifact at deploy.** The
> deployed Worker is Go compiled by TinyGo to Wasm plus the `syumai/workers`
> ES-module shim, emitted by `pnpm run build` into `../build/` (git-ignored,
> produced by CI). Set the **`workerScriptPath`** config to the built main module
> (`../build/worker.mjs`) and the program uploads it via `ContentFile` +
> `ContentSha256` (computed from the file). When `workerScriptPath` is unset, a
> documented placeholder module body is uploaded instead, so the resource is fully
> described and unit-testable without the artifact. The CD workflow
> ([`.github/workflows/deploy.yml`](../.github/workflows/deploy.yml)) builds the
> Worker and injects `workerScriptPath=../build/worker.mjs` at deploy time, so a
> local `pulumi preview` (no build) still works off the placeholder.
>
> Note: a TinyGo Worker is `worker.mjs` (main module) that imports `app.wasm`.
> `ContentFile` uploads the main module; if a functional deploy needs the wasm as a
> separate module part, add it alongside `worker.mjs` in the build output the
> pipeline points at. The bindings/crons below are provider-verified by the mock
> tests regardless of which content source is used.

## Worker bindings

The Worker resource carries the bindings the runtime code reads, matching
`wrangler.jsonc` and the Worker source (`internal/storage.*Binding`,
`worker/*_wasm.go`). This is the wiring #4 added (the gap #9 flagged); the mock
tests (`deploy_test.go`) assert every one of them:

| Binding (JS var) | Type | Points at |
| --- | --- | --- |
| `REPORTS_BUCKET` | `r2_bucket` | `r2BucketName` (`libremail-bug-reports`). Encrypted report objects (ADR 0001). |
| `BUGREPORT_ENC_KEYRING` | `secrets_store_secret` | `secretsStoreId` / secret `bugreport-enc-keyring` — AES-256 keyring (ADR 0001). |
| `ADMIN_TOKEN` | `secrets_store_secret` | `secretsStoreId` / secret `bugreport-admin-token` — admin API token (ADR 0003). |
| `GITHUB_TOKEN` | `secrets_store_secret` | `secretsStoreId` / secret `github-token` — publish PAT (#14). |
| `OTEL_EXPORTER_OTLP_HEADERS` | `secrets_store_secret` | `secretsStoreId` / secret `otel-exporter-otlp-headers` — OTLP auth headers (#17). |
| `GITHUB_REPO` | `plain_text` | `githubRepo` (`JMR-dev/LibreMail`) — publish target (#14). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `plain_text` | `otelExporterOtlpEndpoint` (empty ⇒ telemetry disabled, #17). |
| `OTEL_SERVICE_NAME` | `plain_text` | `otelServiceName` (`libremail-bug-report-ingest`, #17). |

The **Cron Triggers** resource registers both Friday UTC crons (`0 22 * * 5` and
`0 23 * * 5`) from `wrangler.jsonc` (#13); the Worker's scheduled handler gates on
the real America/Chicago rule so exactly one publishes each Friday.

> The Secrets Store **secret values** themselves (keyring, admin token, GitHub
> token, OTLP headers) are **not** created by this stack — the maintainer stores
> them in Cloudflare Secrets Store under `secretsStoreId`. This stack only binds
> them to the Worker by name.

## Prerequisites

- Go (matching the repo toolchain) — `go build ./...` / `go test ./...` work
  without the Pulumi CLI.
- The [Pulumi CLI](https://www.pulumi.com/docs/install/) — required only to
  `pulumi preview` / `pulumi up`. It is **not** installed in CI yet, so a real
  `pulumi preview` is a follow-up (see "Deploying").

## Configuration

Config is per-stack (`Pulumi.<stack>.yaml`). Program keys are namespaced by the
project name, `libremail-bug-report-ingest-infra`. Provider keys use the
`cloudflare:` / `gcp:` namespaces.

### Program config (namespace `libremail-bug-report-ingest-infra`)

| Key | Required | Default | Description |
| --- | --- | --- | --- |
| `cloudflareAccountId` | yes | — | Cloudflare account that owns the Worker + R2 bucket. |
| `secretsStoreId` | yes | — | Cloudflare **Secrets Store id** holding the Worker's secrets (keyring, admin token, GitHub token, OTLP headers). Account-specific; not itself secret. |
| `dnsManagedZone` | yes | — | **Name** of the existing Google Cloud DNS managed zone. |
| `dnsRecordName` | yes | — | Ingest hostname as an FQDN with a trailing dot (e.g. `bugreport.libremail.example.`). |
| `dnsRecordTarget` | yes | — | CNAME target = the Worker route/custom domain (FQDN, trailing dot). |
| `workerName` | no | `libremail-bug-report-ingest` | Worker script name (matches `wrangler.jsonc`). |
| `workerCompatibilityDate` | no | `2025-06-01` | Worker runtime compatibility date. |
| `workerScriptPath` | no | — | Path to the built main module (`../build/worker.mjs`). When set, upload it via `ContentFile` + computed `ContentSha256`. Set by the CD workflow at deploy. |
| `workerScriptContent` | no | placeholder | Inline Worker module body used when `workerScriptPath` is unset. |
| `githubRepo` | no | `JMR-dev/LibreMail` | `GITHUB_REPO` var: `owner/repo` the weekly publish job files issues on (#14). |
| `otelExporterOtlpEndpoint` | no | `""` | `OTEL_EXPORTER_OTLP_ENDPOINT` var: OTLP base URL; empty disables telemetry (#17). |
| `otelServiceName` | no | `libremail-bug-report-ingest` | `OTEL_SERVICE_NAME` var: reported `service.name` (#17). |
| `r2BucketName` | no | `libremail-bug-reports` | R2 bucket name (also the `REPORTS_BUCKET` binding target). |
| `r2BucketLocation` | no | (provider default) | R2 location hint: `apac`, `eeur`, `enam`, `weur`, `wnam`, `oc`. |
| `dnsRecordType` | no | `CNAME` | DNS record type. |
| `dnsTtlSeconds` | no | `300` | DNS record TTL (seconds). |
| `gcpProject` | no | (from `gcp:project`) | Project the record belongs to, if different from the provider project. |
| `cloudflareZoneId` | no | — | **Reserved** for #6/#7 (rate-limit ruleset) and Worker routes/custom domain. Unused today. |

Set a non-secret value with, e.g.:

```console
pulumi config set libremail-bug-report-ingest-infra:cloudflareAccountId <account-id>
```

### Secrets and credentials — DO NOT COMMIT

Set these as **encrypted** Pulumi secrets (`--secret`) or via the provider's
environment variables. Never place plaintext secrets in `Pulumi.<stack>.yaml`.

| What | How | Notes |
| --- | --- | --- |
| Cloudflare API token | `pulumi config set --secret cloudflare:apiToken <token>` (or env `CLOUDFLARE_API_TOKEN`) | Scope it to Workers Scripts + R2 admin for the account. |
| GCP project | `pulumi config set gcp:project <project-id>` | Not secret; identifies the GCP project. |
| GCP credentials | `pulumi config set --secret gcp:credentials "$(cat key.json)"` (or env `GOOGLE_CREDENTIALS` / Application Default Credentials) | Service account with Cloud DNS admin on the zone. |

The **bug-report encryption keyring** (`BUGREPORT_ENC_KEYRING`, see
[ADR 0001](../docs/decisions/encryption.md)) lives in **Cloudflare Secrets
Store**, bound to the Worker — it is managed there, not committed here.

## Deploying

### Via GitHub Actions (recommended)

[`.github/workflows/deploy.yml`](../.github/workflows/deploy.yml) is a
**manual, `workflow_dispatch`-only** CD workflow. A maintainer runs it from the
Actions tab, on the **`main`** branch (a guard step fails otherwise), and picks a
`stack` (default `prod`). It reuses ci.yml's Go/TinyGo/pnpm setup + the TinyGo
net/http patch, runs `pnpm run build`, then `pulumi up --stack <stack>` over this
program (injecting the built `../build/worker.mjs` as `workerScriptPath`). It is
gated to the **`production`** GitHub Actions environment, so that environment's
secrets and any required-reviewer / protection rules apply.

**One-time setup before the first deploy** — the maintainer configures:

1. **`production` environment secrets** (repo Settings → Environments → production):

   | Secret | Purpose |
   | --- | --- |
   | `PULUMI_ACCESS_TOKEN` | Pulumi Cloud token (state backend). Self-managed backend? Use the action's `cloud-url` input + a `PULUMI_CONFIG_PASSPHRASE` secret instead. |
   | `CLOUDFLARE_API_TOKEN` | Cloudflare token scoped to Workers Scripts + R2 (+ Cron Triggers) on the account. |
   | `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account id. |
   | `GOOGLE_CREDENTIALS` | GCP service-account JSON with Cloud DNS admin on the managed zone. |

2. **Stack config** in `Pulumi.<stack>.yaml` — replace every `REPLACE_ME_*`
   (`cloudflareAccountId`, `secretsStoreId`, `dnsManagedZone`, `dnsRecordName`,
   `dnsRecordTarget`, `gcp:project`).

3. **Cloudflare Secrets Store** — under `secretsStoreId`, store the four secret
   values the Worker binds: `bugreport-enc-keyring`, `bugreport-admin-token`,
   `github-token`, `otel-exporter-otlp-headers`.

4. **Pulumi stack** — create it and select it once (`pulumi stack init <stack>`);
   the workflow runs with `upsert: false` and expects it to exist.

**Trigger:** Actions → **CD** → *Run workflow* → branch `main`, stack `prod`.

### Via the Pulumi CLI (manual)

```console
pulumi stack select prod           # or: pulumi stack init prod
# set the REPLACE_ME_* config values + provider secrets above, then build + deploy:
pnpm run build                     # produces ../build/worker.mjs (needed if workerScriptPath is set)
pulumi preview
pulumi up
```

> No real deploy has been run from this repo yet: the mechanism (this program +
> the CD workflow) is **compile-, test-, and actionlint-verified only**. The
> maintainer supplies the credentials/config above and triggers the first deploy.

## Testing (no Pulumi CLI required)

The program is exercised with the Pulumi Go SDK's mocking
(`pulumi.RunErr` + `pulumi.WithMocks`), which registers resources against an
in-memory monitor — no cloud calls, no CLI. The tests assert that the expected
resources are registered with the expected inputs: Worker name/account, its full
**binding set** (R2 `REPORTS_BUCKET`, the four Secrets Store secrets, the three
plain vars) and the **Cron Triggers**, the `ContentFile`/`ContentSha256` artifact
path, R2 bucket name/location, and DNS type/name/target/ttl.

```console
go vet ./...
go build ./...
go test ./...
```

## Adding rate limiting later (#6 ADR / #7 impl)

[The abuse/rate-limit ADR (#6)](../docs/decisions/labels-and-abuse.md) chose to
implement ingest rate limiting as **Cloudflare Rate Limiting rules via Pulumi**
(`cloudflare.NewRuleset`, phase `http_ratelimit`, scoped to a zone). That is out
of scope for this ticket. The `cloudflareZoneId` config key and the forward note
in `deploy.go` leave a clean insertion point; #7 adds the ruleset resource there.
