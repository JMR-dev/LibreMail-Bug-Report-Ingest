package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// testProject is the Pulumi project name used for the mock runs. Program config
// keys are namespaced by it (matches Pulumi.yaml "name").
const testProject = "libremail-bug-report-ingest-infra"

// Resource type tokens registered by the program.
const (
	tokWorkersScript      = "cloudflare:index/workersScript:WorkersScript"
	tokR2Bucket           = "cloudflare:index/r2Bucket:R2Bucket"
	tokWorkersCronTrigger = "cloudflare:index/workersCronTrigger:WorkersCronTrigger"
	tokDNSRecordSet       = "gcp:dns/recordSet:RecordSet"
)

// recordingMocks implements pulumi.MockResourceMonitor, capturing every
// RegisterResource call so tests can assert on the inputs the program sends.
// No provider is ever contacted, so these tests run without the Pulumi CLI.
type recordingMocks struct {
	resources []pulumi.MockResourceArgs
}

func (m *recordingMocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	m.resources = append(m.resources, args)
	// Echo inputs back as the resource's state and synthesize a physical ID.
	return args.Name + "-id", args.Inputs, nil
}

func (m *recordingMocks) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return resource.PropertyMap{}, nil
}

// find returns the first registered resource with the given type token.
func (m *recordingMocks) find(t *testing.T, typeToken string) pulumi.MockResourceArgs {
	t.Helper()
	for _, r := range m.resources {
		if r.TypeToken == typeToken {
			return r
		}
	}
	t.Fatalf("no resource registered with type token %q", typeToken)
	return pulumi.MockResourceArgs{}
}

func key(k string) string { return testProject + ":" + k }

// fullConfig is a complete, valid stack config for the happy-path tests.
func fullConfig() map[string]string {
	return map[string]string{
		key("cloudflareAccountId"): "cf-acct-123",
		key("secretsStoreId"):      "ss-store-xyz",
		key("dnsManagedZone"):      "libremail-zone",
		key("dnsRecordName"):       "bugreport.example.com.",
		key("dnsRecordTarget"):     "libremail-bug-report-ingest.acme.workers.dev.",
		key("r2BucketLocation"):    "enam",
		key("gcpProject"):          "libremail-proj",
	}
}

// runProgram runs deploy under mocks with cfg supplied via PULUMI_CONFIG (the
// same channel the Pulumi CLI uses to pass config to a Go program).
func runProgram(t *testing.T, cfg map[string]string) *recordingMocks {
	t.Helper()
	blob, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	t.Setenv("PULUMI_CONFIG", string(blob))

	m := &recordingMocks{}
	if err := pulumi.RunErr(deploy, pulumi.WithMocks(testProject, "test", m)); err != nil {
		t.Fatalf("pulumi.RunErr: %v", err)
	}
	return m
}

// strProp returns pm[k] as a string, failing the test if it is absent or not a
// string.
func strProp(t *testing.T, pm resource.PropertyMap, k string) string {
	t.Helper()
	v, ok := pm[resource.PropertyKey(k)]
	if !ok {
		t.Fatalf("property %q missing; have %v", k, pm.Mappable())
	}
	if !v.IsString() {
		t.Fatalf("property %q is not a string: %v", k, v)
	}
	return v.StringValue()
}

// objArray returns pm[k] as a slice of PropertyMaps, failing if it is absent or
// not an array of objects. Used to walk the Worker bindings / cron schedules.
func objArray(t *testing.T, pm resource.PropertyMap, k string) []resource.PropertyMap {
	t.Helper()
	v, ok := pm[resource.PropertyKey(k)]
	if !ok || !v.IsArray() {
		t.Fatalf("property %q missing or not an array: %v", k, pm.Mappable())
	}
	out := make([]resource.PropertyMap, 0, len(v.ArrayValue()))
	for i, el := range v.ArrayValue() {
		if !el.IsObject() {
			t.Fatalf("%s[%d] is not an object: %v", k, i, el)
		}
		out = append(out, el.ObjectValue())
	}
	return out
}

// bindingsByName indexes the Worker's bindings array by its "name" (the JS var).
func bindingsByName(t *testing.T, in resource.PropertyMap) map[string]resource.PropertyMap {
	t.Helper()
	out := map[string]resource.PropertyMap{}
	for _, b := range objArray(t, in, "bindings") {
		out[strProp(t, b, "name")] = b
	}
	return out
}

func TestWorkerScriptRegistered(t *testing.T) {
	m := runProgram(t, fullConfig())
	in := m.find(t, tokWorkersScript).Inputs

	if got, want := strProp(t, in, "scriptName"), "libremail-bug-report-ingest"; got != want {
		t.Errorf("scriptName = %q, want %q", got, want)
	}
	if got, want := strProp(t, in, "accountId"), "cf-acct-123"; got != want {
		t.Errorf("accountId = %q, want %q", got, want)
	}
	if got, want := strProp(t, in, "mainModule"), "worker.mjs"; got != want {
		t.Errorf("mainModule = %q, want %q", got, want)
	}
	if got, want := strProp(t, in, "compatibilityDate"), "2025-06-01"; got != want {
		t.Errorf("compatibilityDate = %q, want %q", got, want)
	}
	if got := strProp(t, in, "content"); got == "" {
		t.Error("content is empty; want a non-empty (placeholder) Worker module body")
	}
}

// TestWorkerScriptBindings is the core coverage for #4/#9: the deployed Worker
// must carry the R2 bucket binding, the four Secrets Store bindings, and the
// three plain vars, with the exact names/store/secret_name the Worker reads at
// runtime (wrangler.jsonc contract).
func TestWorkerScriptBindings(t *testing.T) {
	m := runProgram(t, fullConfig())
	in := m.find(t, tokWorkersScript).Inputs
	bindings := bindingsByName(t, in)

	// R2 bucket binding.
	r2, ok := bindings["REPORTS_BUCKET"]
	if !ok {
		t.Fatalf("missing REPORTS_BUCKET binding; have %v", bindingNames(bindings))
	}
	if got, want := strProp(t, r2, "type"), "r2_bucket"; got != want {
		t.Errorf("REPORTS_BUCKET type = %q, want %q", got, want)
	}
	if got, want := strProp(t, r2, "bucketName"), "libremail-bug-reports"; got != want {
		t.Errorf("REPORTS_BUCKET bucketName = %q, want %q", got, want)
	}

	// Secrets Store bindings: name -> secret_name (all share the one store id).
	wantSecrets := map[string]string{
		"BUGREPORT_ENC_KEYRING":      "bugreport-enc-keyring",
		"ADMIN_TOKEN":                "bugreport-admin-token",
		"GITHUB_TOKEN":               "github-token",
		"OTEL_EXPORTER_OTLP_HEADERS": "otel-exporter-otlp-headers",
	}
	for name, wantSecretName := range wantSecrets {
		b, ok := bindings[name]
		if !ok {
			t.Errorf("missing Secrets Store binding %q; have %v", name, bindingNames(bindings))
			continue
		}
		if got, want := strProp(t, b, "type"), "secrets_store_secret"; got != want {
			t.Errorf("%s type = %q, want %q", name, got, want)
		}
		if got, want := strProp(t, b, "storeId"), "ss-store-xyz"; got != want {
			t.Errorf("%s storeId = %q, want %q", name, got, want)
		}
		if got := strProp(t, b, "secretName"); got != wantSecretName {
			t.Errorf("%s secretName = %q, want %q", name, got, wantSecretName)
		}
	}

	// Plain-text vars.
	wantVars := map[string]string{
		"GITHUB_REPO":                 "JMR-dev/LibreMail",
		"OTEL_EXPORTER_OTLP_ENDPOINT": "",
		"OTEL_SERVICE_NAME":           "libremail-bug-report-ingest",
	}
	for name, wantText := range wantVars {
		b, ok := bindings[name]
		if !ok {
			t.Errorf("missing plain var binding %q; have %v", name, bindingNames(bindings))
			continue
		}
		if got, want := strProp(t, b, "type"), "plain_text"; got != want {
			t.Errorf("%s type = %q, want %q", name, got, want)
		}
		if got := textValue(b); got != wantText {
			t.Errorf("%s text = %q, want %q", name, got, wantText)
		}
	}
}

// bindingNames is a small diagnostic helper for failure messages.
func bindingNames(bindings map[string]resource.PropertyMap) []string {
	names := make([]string, 0, len(bindings))
	for n := range bindings {
		names = append(names, n)
	}
	return names
}

// textValue reads a binding's "text" property, treating an absent property as the
// empty string (an empty plain-text var may serialize either way).
func textValue(b resource.PropertyMap) string {
	v, ok := b[resource.PropertyKey("text")]
	if !ok {
		return ""
	}
	if !v.IsString() {
		return ""
	}
	return v.StringValue()
}

// TestWorkerContentFromArtifact verifies the artifact-override path: when
// workerScriptPath is set (as the CD workflow sets it to ../build/worker.mjs
// after `pnpm run build`), the Worker uploads the built file via ContentFile +
// a computed ContentSha256 instead of the inline placeholder content.
func TestWorkerContentFromArtifact(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "worker.mjs")
	body := []byte("export default { async fetch() { return new Response('ok'); } };\n")
	if err := os.WriteFile(artifact, body, 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	sum := sha256.Sum256(body)
	wantSha := hex.EncodeToString(sum[:])

	cfg := fullConfig()
	cfg[key("workerScriptPath")] = artifact
	m := runProgram(t, cfg)
	in := m.find(t, tokWorkersScript).Inputs

	if got, want := strProp(t, in, "contentFile"), artifact; got != want {
		t.Errorf("contentFile = %q, want %q", got, want)
	}
	if got := strProp(t, in, "contentSha256"); got != wantSha {
		t.Errorf("contentSha256 = %q, want %q", got, wantSha)
	}
	if _, ok := in[resource.PropertyKey("content")]; ok {
		t.Error("content should be unset when workerScriptPath drives a ContentFile upload")
	}
	// Bindings must still be attached in the artifact path.
	if _, ok := bindingsByName(t, in)["REPORTS_BUCKET"]; !ok {
		t.Error("REPORTS_BUCKET binding missing on the artifact-content Worker")
	}
}

func TestR2BucketRegistered(t *testing.T) {
	m := runProgram(t, fullConfig())
	in := m.find(t, tokR2Bucket).Inputs

	if got, want := strProp(t, in, "name"), "libremail-bug-reports"; got != want {
		t.Errorf("name = %q, want %q", got, want)
	}
	if got, want := strProp(t, in, "accountId"), "cf-acct-123"; got != want {
		t.Errorf("accountId = %q, want %q", got, want)
	}
	if got, want := strProp(t, in, "location"), "enam"; got != want {
		t.Errorf("location = %q, want %q", got, want)
	}
}

func TestDNSRecordRegistered(t *testing.T) {
	m := runProgram(t, fullConfig())
	in := m.find(t, tokDNSRecordSet).Inputs

	if got, want := strProp(t, in, "managedZone"), "libremail-zone"; got != want {
		t.Errorf("managedZone = %q, want %q", got, want)
	}
	if got, want := strProp(t, in, "name"), "bugreport.example.com."; got != want {
		t.Errorf("name = %q, want %q", got, want)
	}
	if got, want := strProp(t, in, "type"), "CNAME"; got != want {
		t.Errorf("type = %q, want %q", got, want)
	}
	if got, want := strProp(t, in, "project"), "libremail-proj"; got != want {
		t.Errorf("project = %q, want %q", got, want)
	}

	// Default TTL (dnsTtlSeconds unset in fullConfig) should be 300.
	ttl, ok := in[resource.PropertyKey("ttl")]
	if !ok || !ttl.IsNumber() {
		t.Fatalf("ttl missing or not a number: %v", in.Mappable())
	}
	if got := int(ttl.NumberValue()); got != defaultDNSTTLSeconds {
		t.Errorf("ttl = %d, want %d", got, defaultDNSTTLSeconds)
	}

	// Rrdatas should point at the configured Worker target.
	rr, ok := in[resource.PropertyKey("rrdatas")]
	if !ok || !rr.IsArray() {
		t.Fatalf("rrdatas missing or not an array: %v", in.Mappable())
	}
	arr := rr.ArrayValue()
	if len(arr) != 1 || !arr[0].IsString() {
		t.Fatalf("rrdatas = %v, want one string element", rr)
	}
	if got, want := arr[0].StringValue(), "libremail-bug-report-ingest.acme.workers.dev."; got != want {
		t.Errorf("rrdatas[0] = %q, want %q", got, want)
	}
}

// TestWorkerCronTriggers asserts the two Friday UTC crons (#13) are registered as
// a WorkersCronTrigger bound to the ingest Worker.
func TestWorkerCronTriggers(t *testing.T) {
	m := runProgram(t, fullConfig())
	in := m.find(t, tokWorkersCronTrigger).Inputs

	if got, want := strProp(t, in, "scriptName"), "libremail-bug-report-ingest"; got != want {
		t.Errorf("cron scriptName = %q, want %q", got, want)
	}
	if got, want := strProp(t, in, "accountId"), "cf-acct-123"; got != want {
		t.Errorf("cron accountId = %q, want %q", got, want)
	}

	var crons []string
	for _, s := range objArray(t, in, "schedules") {
		crons = append(crons, strProp(t, s, "cron"))
	}
	want := []string{"0 22 * * 5", "0 23 * * 5"}
	if len(crons) != len(want) {
		t.Fatalf("cron schedules = %v, want %v", crons, want)
	}
	for i := range want {
		if crons[i] != want[i] {
			t.Errorf("schedules[%d] = %q, want %q", i, crons[i], want[i])
		}
	}
}

// TestManagedResourceCounts pins the managed resource set: exactly one each of the
// Worker script, R2 bucket, cron trigger, and DNS record.
func TestManagedResourceCounts(t *testing.T) {
	m := runProgram(t, fullConfig())
	counts := map[string]int{}
	for _, r := range m.resources {
		counts[r.TypeToken]++
	}
	for _, tok := range []string{tokWorkersScript, tokR2Bucket, tokWorkersCronTrigger, tokDNSRecordSet} {
		if counts[tok] != 1 {
			t.Errorf("expected exactly 1 %s, got %d", tok, counts[tok])
		}
	}
}

func TestMissingRequiredConfigIsAnError(t *testing.T) {
	// Omit all required keys: loadConfig must return an error and RunErr must
	// surface it rather than registering resources.
	t.Setenv("PULUMI_CONFIG", "{}")
	m := &recordingMocks{}
	err := pulumi.RunErr(deploy, pulumi.WithMocks(testProject, "test", m))
	if err == nil {
		t.Fatal("expected an error for missing required config, got nil")
	}
}
