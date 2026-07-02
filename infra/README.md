# Infrastructure (Pulumi, Go)

Infrastructure-as-code for the LibreMail bug-report ingest pipeline. This is its
own Go module (`github.com/JMR-dev/LibreMail-Bug-Report-Ingest/infra`) so the
Worker module at the repo root stays lean.

It provisions, with the Pulumi Go SDK and the
[`pulumi-cloudflare`](https://www.pulumi.com/registry/packages/cloudflare/) and
[`pulumi-gcp`](https://www.pulumi.com/registry/packages/gcp/) providers:

| Resource | Type | Purpose |
| --- | --- | --- |
| `ingest-worker` | `cloudflare.WorkersScript` | The ingest Worker (`libremail-bug-report-ingest`, built in #1). |
| `reports-bucket` | `cloudflare.R2Bucket` | Encrypted bug-report storage (`libremail-bug-reports`). Per [ADR 0001](../docs/decisions/encryption.md) only ciphertext is written. |
| `ingest-dns-record` | `gcp.dns.RecordSet` | Google Cloud DNS record pointing the ingest hostname at the Worker's route/custom domain. |

DNS authority is **Google Cloud DNS**. The managed zone is **referenced by name**
(it already exists / is managed elsewhere), and this stack only adds a record to
it.

> **Worker content is a placeholder.** The deployed Worker is Go compiled by
> TinyGo to Wasm plus the `syumai/workers` ES-module shim, emitted by
> `pnpm run build` into `../build/` (git-ignored, produced by CI). This program
> ships a documented placeholder module body so the resource is fully described
> and unit-testable without the artifact. Wire the real artifact at deploy time
> via the `workerScriptContent` config, or by setting `ContentFile` /
> `ContentSha256` on the Worker resource to `../build/worker.mjs` in the deploy
> pipeline.

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
| `dnsManagedZone` | yes | — | **Name** of the existing Google Cloud DNS managed zone. |
| `dnsRecordName` | yes | — | Ingest hostname as an FQDN with a trailing dot (e.g. `bugreport.libremail.example.`). |
| `dnsRecordTarget` | yes | — | CNAME target = the Worker route/custom domain (FQDN, trailing dot). |
| `workerName` | no | `libremail-bug-report-ingest` | Worker script name (matches `wrangler.jsonc`). |
| `workerCompatibilityDate` | no | `2025-06-01` | Worker runtime compatibility date. |
| `workerScriptContent` | no | placeholder | Override the Worker module body (normally supplied by the build pipeline). |
| `r2BucketName` | no | `libremail-bug-reports` | R2 bucket name. |
| `r2BucketLocation` | no | (provider default) | R2 location hint: `apac`, `eeur`, `enam`, `weur`, `wnam`, `oc`. |
| `dnsRecordType` | no | `CNAME` | DNS record type. |
| `dnsTtlSeconds` | no | `300` | DNS record TTL (seconds). |
| `gcpProject` | no | (from `gcp:project`) | Project the record belongs to, if different from the provider project. |
| `cloudflareZoneId` | no | — | **Reserved** for #7 (rate-limit ruleset) and Worker routes/custom domain. Unused today. |

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

```console
pulumi stack select dev            # or: pulumi stack init dev
# set the REPLACE_ME_* config values + secrets above, then:
pulumi preview
pulumi up
```

> Deployment is gated behind a maintainer check-in and the Pulumi CLI is not yet
> available in this environment, so this change ships **compile- and
> test-verified only**. Running a real `pulumi preview` against the accounts is a
> follow-up.

## Testing (no Pulumi CLI required)

The program is exercised with the Pulumi Go SDK's mocking
(`pulumi.RunErr` + `pulumi.WithMocks`), which registers resources against an
in-memory monitor — no cloud calls, no CLI. The tests assert that the expected
resources are registered with the expected inputs (Worker name/account, R2 bucket
name/location, DNS type/name/target/ttl).

```console
go vet ./...
go build ./...
go test ./...
```

## Adding rate limiting later (#7)

[The abuse/rate-limit ADR](../docs/decisions/labels-and-abuse.md) chose to
implement ingest rate limiting as **Cloudflare Rate Limiting rules via Pulumi**
(`cloudflare.NewRuleset`, phase `http_ratelimit`, scoped to a zone). That is out
of scope for this ticket. The `cloudflareZoneId` config key and the structure of
`deploy.go` leave a clean insertion point; #7 adds the ruleset resource there.
