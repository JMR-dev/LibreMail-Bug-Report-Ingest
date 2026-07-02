# LibreMail Bug Report Ingest

Server-side infrastructure for [LibreMail](https://github.com/JMR-dev/LibreMail)'s debug
bug-report pipeline. This repo is intentionally separate from the Android app repo — it owns
the Cloudflare Worker and infrastructure-as-code, not the client.

## What this is

Per [JMR-dev/LibreMail#11](https://github.com/JMR-dev/LibreMail/issues/11):

1. The LibreMail app lets a user opt in to submitting a debug report
   ([LibreMail#33](https://github.com/JMR-dev/LibreMail/issues/33)).
2. A Cloudflare Worker in this repo receives the report over HTTPS, best-effort scrubs PII,
   and stores it encrypted in a Cloudflare R2 bucket
   ([#34](https://github.com/JMR-dev/LibreMail/issues/34)).
3. Every Friday at 17:00 (Central Time, DST-aware), a scheduled job publishes any report not
   manually removed as a GitHub issue on the LibreMail repo
   ([#35](https://github.com/JMR-dev/LibreMail/issues/35)).

## Stack

- Worker: Go, compiled to WebAssembly with [TinyGo](https://tinygo.org) and served through the [`syumai/workers`](https://github.com/syumai/workers) runtime adapter
- Infrastructure as code: Pulumi (Go)
- Deployment: GitHub Actions
- Secrets/key custody: Cloudflare Secret Manager
- DNS: Google Cloud DNS

## Build & run locally

The request-handling logic lives in `internal/handler` as plain, build-tag-free
Go, so it is unit-tested and run locally with the standard Go toolchain — no
TinyGo needed. Only the actual Wasm Worker build requires TinyGo.

Layout:

- `internal/handler/` — the core `http.Handler` (health/hello endpoints). No build tags; all request logic and its tests live here.
- `cmd/devserver/` — a plain `net/http` server that mounts the core handler for local dev without TinyGo.
- `worker/` — the Cloudflare Workers (Wasm) entrypoint, guarded by `//go:build js && wasm`, wiring the same core handler into the Workers runtime. Excluded from host builds and tests.

### Test

```console
go vet ./...
go test ./...
```

### Run locally (no TinyGo)

```console
go run ./cmd/devserver   # listens on :8787; override with ADDR, e.g. ADDR=:9000
```

Then, from another shell:

```console
$ curl -s localhost:8787/
{"service":"libremail-bug-report-ingest","status":"ok","message":"hello from the LibreMail bug-report ingest Worker"}
$ curl -s localhost:8787/healthz
{"status":"ok"}
```

This runs the exact handler the deployed Worker uses, minus the Workers runtime.

### Build & run the real Worker (requires TinyGo)

Node tooling is managed with **pnpm**; wrangler is a dev dependency. The Wasm
build uses [TinyGo](https://tinygo.org) 0.35.0+.

```console
pnpm install                 # install wrangler
pnpm run build               # workers-assets-gen + TinyGo -> ./build/app.wasm + ./build/worker.mjs
pnpm exec wrangler dev       # serve the Wasm Worker locally on :8787
pnpm exec wrangler deploy    # deploy (CI only)
```

`pnpm run build` runs, verbatim:

```console
go run github.com/syumai/workers/cmd/workers-assets-gen && tinygo build -o ./build/app.wasm -target wasm -no-debug ./worker
```

TinyGo is **not** required for tests or the dev server; it is needed only for the
Wasm build above and is installed in CI. The generated `./build/` output is
git-ignored.

### Why TinyGo + `syumai/workers`

Cloudflare Workers execute WebAssembly, not native binaries, so Go must be
compiled to Wasm. Of the two options — the standard compiler's
`GOOS=js GOARCH=wasm` output or TinyGo — TinyGo emits far smaller modules that
sit comfortably inside the Worker size limit, which is why it is the standard
path for Go on Workers. The [`syumai/workers`](https://github.com/syumai/workers)
package adapts Go's `net/http` handler model to the Workers `fetch` event, so a
single `http.Handler` runs unchanged on the dev server and in the deployed
Worker.

## Status

Early bootstrap. See the [project board](../../projects) and
[open issues](../../issues) for the current breakdown of work.

## License

[GNU AGPL v3.0](LICENSE).
