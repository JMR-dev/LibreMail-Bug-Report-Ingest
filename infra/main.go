// Command infra is the Pulumi (Go) entrypoint for the LibreMail bug-report
// ingest infrastructure.
//
// It provisions the three pieces of edge/DNS infrastructure the pipeline needs:
//
//   - the Cloudflare Worker script that receives bug reports (built in #1),
//   - the Cloudflare R2 bucket that stores the encrypted reports (ADR 0001),
//   - the Google Cloud DNS record that points the ingest hostname at the Worker.
//
// The program is a thin wrapper: all resource wiring lives in deploy, which is
// exercised directly by the mock-based unit tests in deploy_test.go (no Pulumi
// CLI required). See infra/README.md for the config/secrets a deployer supplies.
package main

import "github.com/pulumi/pulumi/sdk/v3/go/pulumi"

func main() {
	pulumi.Run(deploy)
}
