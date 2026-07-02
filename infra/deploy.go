package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi-gcp/sdk/v8/go/gcp/dns"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

// Logical (Pulumi) resource names. Stable across deploys and asserted by
// deploy_test.go, so treat them as part of the program's contract.
const (
	resWorker      = "ingest-worker"
	resR2Bucket    = "reports-bucket"
	resDNSRecord   = "ingest-dns-record"
	resCronTrigger = "ingest-cron-triggers"
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

// Worker binding names and runtime var defaults. These mirror wrangler.jsonc and
// the names the Worker code reads at runtime (internal/storage.*Binding,
// worker/*_wasm.go), so the deployed Worker actually has the R2 bucket, the
// Secrets Store secrets, and the plain vars it expects. Changing a binding *name*
// here is a breaking change to the Worker contract.
const (
	// JS variable (binding) names the Worker reads via env.<name>.
	bindingR2Bucket    = "REPORTS_BUCKET"              // R2 bucket (internal/storage.BucketBinding)
	bindingEncKeyring  = "BUGREPORT_ENC_KEYRING"       // Secrets Store: AES keyring (ADR 0001)
	bindingAdminToken  = "ADMIN_TOKEN"                 // Secrets Store: admin API bearer token (ADR 0003)
	bindingGitHubToken = "GITHUB_TOKEN"                // Secrets Store: publish PAT (#14)
	bindingOtelHeaders = "OTEL_EXPORTER_OTLP_HEADERS"  // Secrets Store: OTLP auth headers (#17)
	varGitHubRepo      = "GITHUB_REPO"                 // plain var: "owner/repo" publish target (#14)
	varOtelEndpoint    = "OTEL_EXPORTER_OTLP_ENDPOINT" // plain var: OTLP base URL, "" disables (#17)
	varOtelServiceName = "OTEL_SERVICE_NAME"           // plain var: reported service.name (#17)

	// Secrets Store secret_name values (the names of the stored secrets), from
	// wrangler.jsonc secrets_store_secrets. The store_id is account-specific and
	// supplied via the secretsStoreId config.
	secretNameEncKeyring  = "bugreport-enc-keyring"
	secretNameAdminToken  = "bugreport-admin-token"
	secretNameGitHubToken = "github-token"
	secretNameOtelHeaders = "otel-exporter-otlp-headers"

	// Cloudflare multipart binding "type" discriminators.
	// https://developers.cloudflare.com/workers/configuration/multipart-upload-metadata/#bindings
	bindingTypeR2Bucket     = "r2_bucket"
	bindingTypeSecretsStore = "secrets_store_secret"
	bindingTypePlainText    = "plain_text"

	// Runtime var defaults (match wrangler.jsonc "vars").
	defaultGitHubRepo      = "JMR-dev/LibreMail"
	defaultOtelServiceName = "libremail-bug-report-ingest"
)

// defaultCronSchedules are the two Friday UTC Cron Triggers from wrangler.jsonc
// (#13). Cloudflare crons are UTC-only and 17:00 America/Chicago is a different
// UTC hour under CDT vs CST, so BOTH candidate hours are registered; the Worker's
// scheduled handler (internal/schedule.IsFriday1700Central) gates each fire so
// exactly one does the weekly publish and the other is a no-op.
var defaultCronSchedules = []string{
	"0 22 * * 5", // Fridays 22:00 UTC == 17:00 Central during CDT (summer)
	"0 23 * * 5", // Fridays 23:00 UTC == 17:00 Central during CST (winter)
}

// placeholderWorkerScript is a stand-in module body for the Worker.
//
// The deployed Worker is Go compiled by TinyGo to Wasm plus the syumai/workers
// ES-module shim, emitted by `pnpm run build` into ../build/ (git-ignored,
// produced by CI). The real, functional deploy uploads that built artifact by
// setting the `workerScriptPath` config (the CD workflow sets it to
// ../build/worker.mjs after `pnpm run build`), which switches the resource to
// ContentFile + ContentSha256. When `workerScriptPath` is unset this documented
// placeholder is uploaded instead, so the resource is fully described and
// unit-testable without the artifact present. Override the placeholder body with
// the `workerScriptContent` config. See infra/README.md.
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
	// Worker routes / custom domains and the ingest rate-limit ruleset (#6/#7) can
	// be added later without a config change. See the forward note in deploy.
	cloudflareZoneId string

	workerName        string
	workerContent     string
	workerScriptPath  string // optional path to the built main module; enables ContentFile upload
	compatibilityDate string

	// secretsStoreId is the Cloudflare Secrets Store id that holds the Worker's
	// secrets (keyring, admin token, GitHub token, OTLP headers). Account-specific,
	// so required; it is NOT itself a secret (it is an id, like the account id).
	secretsStoreId string

	// Plain (non-secret) Worker vars.
	githubRepo      string
	otelEndpoint    string
	otelServiceName string

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
	secretsStoreID, err := cfg.Try("secretsStoreId")
	if err != nil {
		return nil, fmt.Errorf("config secretsStoreId: %w", err)
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
		workerScriptPath:    cfg.Get("workerScriptPath"),
		compatibilityDate:   getOr(cfg, "workerCompatibilityDate", defaultCompatibilityDate),
		secretsStoreId:      secretsStoreID,
		githubRepo:          getOr(cfg, "githubRepo", defaultGitHubRepo),
		otelEndpoint:        cfg.Get("otelExporterOtlpEndpoint"),
		otelServiceName:     getOr(cfg, "otelServiceName", defaultOtelServiceName),
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

// fileSha256 returns the lowercase hex SHA-256 of the file at path. It is used to
// derive ContentSha256 for the Worker artifact upload; the Cloudflare provider
// requires ContentSha256 whenever ContentFile is set (it triggers an update when
// the built Wasm changes).
func fileSha256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// workerBindings returns the full binding set the Worker needs at runtime: the R2
// bucket, the four Cloudflare Secrets Store secrets, and the three plain vars.
// This is the #9-flagged wiring gap that #4 closes — before this the deployed
// Worker had no bindings and could not read its bucket/secrets/vars.
func workerBindings(cfg *infraConfig) cloudflare.WorkersScriptBindingArray {
	return cloudflare.WorkersScriptBindingArray{
		// R2 bucket: env.REPORTS_BUCKET -> the encrypted-report bucket (ADR 0001).
		&cloudflare.WorkersScriptBindingArgs{
			Name:       pulumi.String(bindingR2Bucket),
			Type:       pulumi.String(bindingTypeR2Bucket),
			BucketName: pulumi.String(cfg.r2BucketName),
		},
		// Secrets Store secrets, read at runtime via env.<name>.get().
		secretsStoreBinding(bindingEncKeyring, cfg.secretsStoreId, secretNameEncKeyring),
		secretsStoreBinding(bindingAdminToken, cfg.secretsStoreId, secretNameAdminToken),
		secretsStoreBinding(bindingGitHubToken, cfg.secretsStoreId, secretNameGitHubToken),
		secretsStoreBinding(bindingOtelHeaders, cfg.secretsStoreId, secretNameOtelHeaders),
		// Plain (non-secret) vars, read via cloudflare.Getenv(<name>).
		plainTextBinding(varGitHubRepo, cfg.githubRepo),
		plainTextBinding(varOtelEndpoint, cfg.otelEndpoint),
		plainTextBinding(varOtelServiceName, cfg.otelServiceName),
	}
}

// secretsStoreBinding builds one Cloudflare Secrets Store binding (env.<name>.get()).
func secretsStoreBinding(name, storeID, secretName string) cloudflare.WorkersScriptBindingInput {
	return &cloudflare.WorkersScriptBindingArgs{
		Name:       pulumi.String(name),
		Type:       pulumi.String(bindingTypeSecretsStore),
		StoreId:    pulumi.String(storeID),
		SecretName: pulumi.String(secretName),
	}
}

// plainTextBinding builds one plain-text (non-secret) var binding.
func plainTextBinding(name, text string) cloudflare.WorkersScriptBindingInput {
	return &cloudflare.WorkersScriptBindingArgs{
		Name: pulumi.String(name),
		Type: pulumi.String(bindingTypePlainText),
		Text: pulumi.String(text),
	}
}

// deploy registers all resources for the bug-report ingest stack.
func deploy(ctx *pulumi.Context) error {
	cfg, err := loadConfig(ctx)
	if err != nil {
		return err
	}

	// 1. Cloudflare Worker script - the ingest Worker built in #1, now wired with
	//    its full binding set (R2 + Secrets Store + vars). Content is the real
	//    built artifact when workerScriptPath is set (the CD workflow points it at
	//    ../build/worker.mjs after `pnpm run build`); otherwise a documented
	//    placeholder module body (see placeholderWorkerScript).
	scriptArgs := &cloudflare.WorkersScriptArgs{
		AccountId:         pulumi.String(cfg.cloudflareAccountId),
		ScriptName:        pulumi.String(cfg.workerName),
		MainModule:        pulumi.String(mainModule),
		CompatibilityDate: pulumi.String(cfg.compatibilityDate),
		Bindings:          workerBindings(cfg),
	}
	if cfg.workerScriptPath != "" {
		sum, err := fileSha256(cfg.workerScriptPath)
		if err != nil {
			return fmt.Errorf("worker script artifact %q: %w", cfg.workerScriptPath, err)
		}
		scriptArgs.ContentFile = pulumi.String(cfg.workerScriptPath)
		scriptArgs.ContentSha256 = pulumi.String(sum)
	} else {
		scriptArgs.Content = pulumi.String(cfg.workerContent)
	}
	worker, err := cloudflare.NewWorkersScript(ctx, resWorker, scriptArgs)
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

	// 3. Cloudflare Cron Triggers for the weekly publish job (#13). Both Friday UTC
	//    hours are registered (DST straddle); the Worker's scheduled handler gates
	//    which one publishes. Depends on the Worker script it schedules.
	schedules := cloudflare.WorkersCronTriggerScheduleArray{}
	for _, cron := range defaultCronSchedules {
		schedules = append(schedules, &cloudflare.WorkersCronTriggerScheduleArgs{
			Cron: pulumi.String(cron),
		})
	}
	if _, err := cloudflare.NewWorkersCronTrigger(ctx, resCronTrigger, &cloudflare.WorkersCronTriggerArgs{
		AccountId:  pulumi.String(cfg.cloudflareAccountId),
		ScriptName: worker.ScriptName,
		Schedules:  schedules,
	}); err != nil {
		return fmt.Errorf("cron triggers: %w", err)
	}

	// 4. Google Cloud DNS record pointing the ingest hostname at the Worker's
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

	// Forward note (#6 ADR docs/decisions/labels-and-abuse.md / #7 impl): the
	// accepted ADR implements ingest rate limiting as Cloudflare Rate Limiting
	// rules via Pulumi (cloudflare.NewRuleset with Phase "http_ratelimit", scoped
	// to cloudflareZoneId). That is out of scope for this ticket, but the config
	// (cloudflareZoneId) and this structure leave a clean insertion point: add the
	// ruleset resource here. Worker routes / a custom domain would attach the same
	// way via cloudflareZoneId.

	ctx.Export("workerName", worker.ScriptName)
	ctx.Export("workerAccountId", worker.AccountId)
	ctx.Export("r2BucketName", bucket.Name)
	ctx.Export("cronSchedules", pulumi.ToStringArray(defaultCronSchedules))
	ctx.Export("dnsRecordFqdn", record.Name)
	ctx.Export("dnsRecordTargets", record.Rrdatas)
	if cfg.cloudflareZoneId != "" {
		ctx.Export("cloudflareZoneId", pulumi.String(cfg.cloudflareZoneId))
	}

	return nil
}
