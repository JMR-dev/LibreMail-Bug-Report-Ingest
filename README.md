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

- Worker: Go
- Infrastructure as code: Pulumi (Go)
- Deployment: GitHub Actions
- Secrets/key custody: Cloudflare Secret Manager
- DNS: Google Cloud DNS

## Status

Early bootstrap. See the [project board](../../projects) and
[open issues](../../issues) for the current breakdown of work.

## License

[GNU AGPL v3.0](LICENSE).
