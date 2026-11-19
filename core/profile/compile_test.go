package profile

import (
	"encoding/json"
	"strings"
	"testing"
)

const fixture = `
dns:
  nameserver: [https://example.invalid/dns-query]
  default-nameserver: [192.0.2.53]
proxies:
  - {name: test-node, type: vless, server: example.invalid, port: 443, uuid: df10688e-614b-4dd0-876a-a106b726532e, tls: !!bool true, udp: true, network: tcp, flow: xtls-rprx-vision}
proxy-groups:
  - {name: test-group, type: select, proxies: [DIRECT, test-node]}
rules:
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - DOMAIN-SUFFIX,example.invalid,test-group
  - MATCH,test-group
`

func TestCompileEnvelope(t *testing.T) {
	envelope, report, err := Compile([]byte(fixture), nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Nodes != 1 || report.Groups != 1 || report.DisabledGroupChoices != 1 || report.IgnoredRules != 2 || report.StaticDirectCIDRs != 1 {
		t.Fatalf("report: %+v", report)
	}
	var config map[string]any
	if err = json.Unmarshal([]byte(envelope.CoreJSON), &config); err != nil {
		t.Fatal(err)
	}
	outbounds := config["outbounds"].([]any)
	if _, restricted := outbounds[0].(map[string]any)["network"]; restricted {
		t.Fatal("Clash TCP transport must not disable UDP in sing-box")
	}
	if len(outbounds) != 2 || len(envelope.DNSServers) != 1 {
		t.Fatal("missing envelope data")
	}
	raw, _ := json.Marshal(report)
	if strings.Contains(string(raw), "example.invalid") || strings.Contains(string(raw), "df10688e") {
		t.Fatal("sensitive report")
	}
}

func TestRejectInvalidReferencesAndParameters(t *testing.T) {
	for _, input := range []string{
		strings.Replace(fixture, "[DIRECT, test-node]", "[test-group]", 1),
		strings.Replace(fixture, "[DIRECT, test-node]", "[missing]", 1),
		strings.Replace(fixture, "[DIRECT, test-node]", "[DIRECT]", 1),
		strings.Replace(fixture, "tls: !!bool true", "tls: false", 1),
		strings.Replace(fixture, "port: 443", "port: 0", 1),
		strings.Replace(fixture, "network: tcp", "network: ws", 1),
		strings.Replace(fixture, "network: tcp", "network: tcp, plugin: unknown", 1),
		fixture + "\n---\n{}",
		"proxies: [invalid",
	} {
		if _, _, err := Compile([]byte(input), nil); err == nil {
			t.Fatal("accepted invalid configuration")
		}
	}
}
