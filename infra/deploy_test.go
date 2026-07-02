package main

import (
	"encoding/json"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// testProject is the Pulumi project name used for the mock runs. Program config
// keys are namespaced by it (matches Pulumi.yaml "name").
const testProject = "libremail-bug-report-ingest-infra"

// Resource type tokens registered by the program.
const (
	tokWorkersScript = "cloudflare:index/workersScript:WorkersScript"
	tokR2Bucket      = "cloudflare:index/r2Bucket:R2Bucket"
	tokDNSRecordSet  = "gcp:dns/recordSet:RecordSet"
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

func TestExactlyThreeManagedResources(t *testing.T) {
	m := runProgram(t, fullConfig())
	counts := map[string]int{}
	for _, r := range m.resources {
		counts[r.TypeToken]++
	}
	for _, tok := range []string{tokWorkersScript, tokR2Bucket, tokDNSRecordSet} {
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
