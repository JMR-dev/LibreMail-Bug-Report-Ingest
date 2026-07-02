package main

import (
	"errors"
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi-gcp/sdk/v8/go/gcp/dns"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

// Logical (Pulumi) resource names. Stable across deploys and asserted by
// deploy_test.go, so treat them as part of the program's contract.
const (
	resWorker    = "ingest-worker"
	resR2Bucket  = "reports-bucket"
	resDNSRecord = "ingest-dns-record"
)

// Defaults for config values that have a sensible project-wide default. Values
// that identify a specific Cloudflare account, GCP project, DNS zone, or
// hostname have no safe default and are required (see loadConfig).
const (
	// defaultWorkerName matches wrangler.jsonc "name" and the Worker built in #1.
	defaultWorkerName = "libremail-bug-report-ingest"
	// defaultR2BucketName is the encrypted-report bucket (ADR 0001).
	defaultR2BucketName = "libremail-bug-reports"
	// defaultCompatibilityDate matches wrangler.jsonc "compatibility_date".
	defaultCompatibilityDate = "2025-06-01"
	// mainModule is the ES-module entry emitted alongside the Wasm build.
	mainModule = "worker.mjs"

	defaultDNSRecordType = "CNAME"
	defaultDNSTTLSeconds = 300
)

// placeholderWorkerScript is a stand-in module body for the Worker.
//
// The deployed Worker is Go compiled by TinyGo to Wasm plus the syumai/workers
// ES-module shim, emitted by `pnpm run build` into ../build/ (git-ignored,
// produced by CI). Uploading that multipart Wasm artifact is the build/deploy
// pipeline's job; this program ships a documented placeholder so the resource is
// fully described and unit-testable without the artifact present. Override it at
// deploy time with the `workerScriptContent` config, or wire the real artifact
// via ContentFile/ContentSha256 in the deploy pipeline. See infra/README.md.
const placeholderWorkerScript = `// PLACEHOLDER - replaced at deploy time by the TinyGo -> Wasm build (see repo README).
export default {
  async fetch() {
    return new Response("libremail-bug-report-ingest: placeholder worker; real build is produced by TinyGo.\n", { status: 501 });
  },
};
`

// infraConfig is the fully-resolved configuration for one stack. It is loaded
// from pulumi.Config (the project-namespaced keys) plus provider config
// (cloudflare:*, gcp:*) that the SDK reads directly.
type infraConfig struct {
	// cloudflareAccountId is the Cloudflare account that owns the Worker + bucket.
	cloudflareAccountId string
	// cloudflareZoneId is optional and unused today. It is reserved so that
	// Worker routes / custom domains and the ingest rate-limit ruleset (#7) can
	// be added later without a config change. See the forward note in deploy.
	cloudflareZoneId string

	workerName        string
	workerContent     string
	compatibilityDate string

	r2BucketName     string
	r2BucketLocation string // optional; Cloudflare picks a location when empty

	// gcpProject is optional; when empty the record inherits the gcp:project
	// provider config.
	gcpProject      string
	dnsManagedZone  string
	dnsRecordName   string
	dnsRecordType   string
	dnsRecordTarget string
	dnsTTLSeconds   int
}

// loadConfig resolves the stack configuration, returning an error (rather than
// exiting) when a required key is missing so the program is testable.
func loadConfig(ctx *pulumi.Context) (*infraConfig, error) {
	cfg := config.New(ctx, "")

	accountID, err := cfg.Try("cloudflareAccountId")
	if err != nil {
		return nil, fmt.Errorf("config cloudflareAccountId: %w", err)
	}
	managedZone, err := cfg.Try("dnsManagedZone")
	if err != nil {
		return nil, fmt.Errorf("config dnsManagedZone: %w", err)
	}
	recordName, err := cfg.Try("dnsRecordName")
	if err != nil {
		return nil, fmt.Errorf("config dnsRecordName: %w", err)
	}
	recordTarget, err := cfg.Try("dnsRecordTarget")
	if err != nil {
		return nil, fmt.Errorf("config dnsRecordTarget: %w", err)
	}

	ttl := defaultDNSTTLSeconds
	if v, err := cfg.TryInt("dnsTtlSeconds"); err == nil {
		ttl = v
	} else if !errors.Is(err, config.ErrMissingVar) {
		return nil, fmt.Errorf("config dnsTtlSeconds: %w", err)
	}

	return &infraConfig{
		cloudflareAccountId: accountID,
		cloudflareZoneId:    cfg.Get("cloudflareZoneId"),
		workerName:          getOr(cfg, "workerName", defaultWorkerName),
		workerContent:       getOr(cfg, "workerScriptContent", placeholderWorkerScript),
		compatibilityDate:   getOr(cfg, "workerCompatibilityDate", defaultCompatibilityDate),
		r2BucketName:        getOr(cfg, "r2BucketName", defaultR2BucketName),
		r2BucketLocation:    cfg.Get("r2BucketLocation"),
		gcpProject:          cfg.Get("gcpProject"),
		dnsManagedZone:      managedZone,
		dnsRecordName:       recordName,
		dnsRecordType:       getOr(cfg, "dnsRecordType", defaultDNSRecordType),
		dnsRecordTarget:     recordTarget,
		dnsTTLSeconds:       ttl,
	}, nil
}

// getOr returns the config value for key, or def when it is unset/empty.
func getOr(cfg *config.Config, key, def string) string {
	if v := cfg.Get(key); v != "" {
		return v
	}
	return def
}

// deploy registers all resources for the bug-report ingest stack.
func deploy(ctx *pulumi.Context) error {
	cfg, err := loadConfig(ctx)
	if err != nil {
		return err
	}

	// 1. Cloudflare Worker script - the ingest Worker built in #1. Content is a
	//    documented placeholder; the real Wasm artifact is uploaded by the build
	//    pipeline (see placeholderWorkerScript).
	worker, err := cloudflare.NewWorkersScript(ctx, resWorker, &cloudflare.WorkersScriptArgs{
		AccountId:         pulumi.String(cfg.cloudflareAccountId),
		ScriptName:        pulumi.String(cfg.workerName),
		Content:           pulumi.String(cfg.workerContent),
		MainModule:        pulumi.String(mainModule),
		CompatibilityDate: pulumi.String(cfg.compatibilityDate),
	})
	if err != nil {
		return fmt.Errorf("worker script: %w", err)
	}

	// 2. Cloudflare R2 bucket for the encrypted bug-report objects. Per ADR 0001
	//    the Worker encrypts each report with AES-256-GCM before writing, so only
	//    ciphertext is ever stored here.
	bucketArgs := &cloudflare.R2BucketArgs{
		AccountId: pulumi.String(cfg.cloudflareAccountId),
		Name:      pulumi.String(cfg.r2BucketName),
	}
	if cfg.r2BucketLocation != "" {
		bucketArgs.Location = pulumi.String(cfg.r2BucketLocation)
	}
	bucket, err := cloudflare.NewR2Bucket(ctx, resR2Bucket, bucketArgs)
	if err != nil {
		return fmt.Errorf("r2 bucket: %w", err)
	}

	// 3. Google Cloud DNS record pointing the ingest hostname at the Worker's
	//    route/custom domain. DNS authority is Google Cloud DNS; the managed zone
	//    is referenced by name (it is managed outside this stack) and a record is
	//    added to it.
	recordArgs := &dns.RecordSetArgs{
		ManagedZone: pulumi.String(cfg.dnsManagedZone),
		Name:        pulumi.String(cfg.dnsRecordName),
		Type:        pulumi.String(cfg.dnsRecordType),
		Ttl:         pulumi.Int(cfg.dnsTTLSeconds),
		Rrdatas:     pulumi.StringArray{pulumi.String(cfg.dnsRecordTarget)},
	}
	if cfg.gcpProject != "" {
		recordArgs.Project = pulumi.String(cfg.gcpProject)
	}
	record, err := dns.NewRecordSet(ctx, resDNSRecord, recordArgs)
	if err != nil {
		return fmt.Errorf("dns record: %w", err)
	}

	// Forward note (#7 / docs/decisions/labels-and-abuse.md): the accepted ADR
	// implements ingest rate limiting as Cloudflare Rate Limiting rules via
	// Pulumi (cloudflare.NewRuleset with Phase "http_ratelimit", scoped to
	// cloudflareZoneId). That is out of scope for #2, but the config
	// (cloudflareZoneId) and this structure leave a clean insertion point:
	// add the ruleset resource here. Worker routes / a custom domain would
	// attach the same way via cloudflareZoneId.

	ctx.Export("workerName", worker.ScriptName)
	ctx.Export("workerAccountId", worker.AccountId)
	ctx.Export("r2BucketName", bucket.Name)
	ctx.Export("dnsRecordFqdn", record.Name)
	ctx.Export("dnsRecordTargets", record.Rrdatas)
	if cfg.cloudflareZoneId != "" {
		ctx.Export("cloudflareZoneId", pulumi.String(cfg.cloudflareZoneId))
	}

	return nil
}
