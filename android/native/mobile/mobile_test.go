package mobile

import (
	"encoding/json"
	"strings"
	"testing"
)

const fixture = `proxies:
  - name: test-node
    type: vless
    server: node.invalid
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    tls: true
    udp: true
    servername: example.org
    flow: xtls-rprx-vision
    client-fingerprint: chrome
proxy-groups:
  - name: default-group
    type: select
    proxies: [test-node, DIRECT]
rules: [MATCH,default-group]
`

// YAML flow-style MATCH needs to be a single scalar.
func sample() string {
	return strings.Replace(fixture, "rules: [MATCH,default-group]", "rules: ['MATCH,default-group']", 1)
}

func TestCompileBoundary(t *testing.T) {
	data, info, err := compiled(sample(), "test-node", "{}", "ali")
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Nodes) != 1 || len(info.Groups["default-group"]) != 1 {
		t.Fatal("unexpected metadata")
	}
	var config map[string]any
	if json.Unmarshal(data, &config) != nil {
		t.Fatal("invalid output")
	}
	if config["route"].(map[string]any)["final"] != "test-node" {
		t.Fatal("wrong exit")
	}
	if config["route"].(map[string]any)["auto_detect_interface"] != true {
		t.Fatal("platform socket protection was not enabled")
	}
	if strings.Contains(string(data), "node.invalid") == false {
		t.Fatal("endpoint missing")
	}
	public, err := Inspect(sample())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"00000000-0000", "node.invalid", "example.org"} {
		if strings.Contains(public, secret) {
			t.Fatal("metadata contains private endpoint or credentials")
		}
	}
	for _, test := range []struct{ source, exit, choices, dns string }{
		{sample(), "DIRECT", "{}", "ali"},
		{sample(), "test-node", `{"default-group":"DIRECT"}`, "ali"},
		{sample(), "test-node", `{"unknown":"test-node"}`, "ali"},
		{sample(), "test-node", "{}", "https://attacker.invalid"},
		{strings.Repeat("x", 1048577), "", "{}", "ali"},
		{sample(), "", strings.Repeat("x", 65537), "ali"},
		{strings.Replace(sample(), "tls: true", "tls: false", 1), "", "{}", "ali"},
		{strings.Replace(sample(), "udp: true", "udp: true\n    skip-cert-verify: true", 1), "", "{}", "ali"},
	} {
		if _, _, err := compiled(test.source, test.exit, test.choices, test.dns); err == nil {
			t.Fatal("unsafe input accepted")
		}
	}
}
func TestImportedRuntimeFeaturesNeverExecute(t *testing.T) {
	source := sample() + "\nexternal-controller: 0.0.0.0:9090\nmixed-port: 12345\ntun:\n  enable: true\nrule-providers:\n  remote:\n    url: https://attacker.invalid/rules\n"
	data, _, err := compiled(source, "", "{}", "cloudflare")
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"attacker", "9090", "12345", "external-controller", "rule_set", "mixed"} {
		if strings.Contains(string(data), needle) {
			t.Fatal("external runtime feature retained")
		}
	}
}
func TestMissingTunnel(t *testing.T) {
	if _, err := Start(sample(), "", "{}", "ali", -1, nil); err == nil {
		t.Fatal("missing tunnel accepted")
	}
}

func TestSubscriptionLabelLimits(t *testing.T) {
	for _, name := range []string{strings.Repeat("a", 513), "unsafe\u202ename", "unsafe\u2066name"} {
		source := strings.ReplaceAll(sample(), "test-node", name)
		if _, _, err := compiled(source, "", "{}", "ali"); err == nil {
			t.Fatal("unsafe display label accepted")
		}
	}
	if _, _, err := compiled(strings.ReplaceAll(sample(), "node.invalid", strings.Repeat("a", 254)), "", "{}", "ali"); err == nil {
		t.Fatal("oversized server name accepted")
	}
}
func FuzzInspect(f *testing.F) {
	f.Add(sample())
	f.Add("!!map {}")
	f.Add("proxies: [*recursive]")
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > 1048577 {
			return
		}
		_, _ = Inspect(source)
	})
}
