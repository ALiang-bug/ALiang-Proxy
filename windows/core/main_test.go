package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSubscriptionDisplayNameValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{"美国 LA-三网优", true},
		{strings.Repeat("a", 512), true},
		{strings.Repeat("a", 513), false},
		{"node\\tname", false},
		{"node\u202ename", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := strings.Replace(lifecycleFixture, "name: offline-node", "name: \""+tc.name+"\"", 1)
			source = strings.Replace(source, "rules:\n  - MATCH,offline-node\n", "", 1)
			_, _, err := configuration(request{YAML: source, Port: 17890})
			if (err == nil) != tc.valid {
				t.Fatalf("unexpected validation result: %v", err)
			}
		})
	}
}

func TestNodeResolverConfigurationLoads(t *testing.T) {
	for _, resolver := range []string{"system", "ali", "cloudflare"} {
		t.Run(resolver, func(t *testing.T) {
			data, _, err := configuration(request{YAML: lifecycleFixture, Port: 17890, Resolver: resolver})
			if err != nil {
				t.Fatal(err)
			}
			var config map[string]json.RawMessage
			if err := json.Unmarshal(data, &config); err != nil {
				t.Fatal(err)
			}
			if _, configured := config["dns"]; configured != (resolver != "system") {
				t.Fatal("unexpected DNS configuration")
			}
			// Load the actual core registries without binding a listener or sending queries.
			delete(config, "inbounds")
			data, err = json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			core, err := newCore(context.Background(), data)
			if err != nil {
				t.Fatal(err)
			}
			if err := core.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, _, err := configuration(request{YAML: lifecycleFixture, Port: 17890, Resolver: "https://example.invalid"}); err == nil {
		t.Fatal("unrecognized resolver accepted")
	}
}

func TestReportedDefaultExitMatchesRoute(t *testing.T) {
	source := lifecycleFixture + `
proxy-groups:
  - name: picked-group
    type: select
    proxies: [offline-node]
`
	source = strings.Replace(source, "MATCH,offline-node", "MATCH,picked-group", 1)
	for _, tc := range []struct{ override, want string }{
		{"", "picked-group"},
		{"offline-node", "offline-node"},
	} {
		_, exits, err := configuration(request{YAML: source, Exit: tc.override, Port: 17890})
		if err != nil {
			t.Fatal(err)
		}
		var defaults []string
		for _, exit := range exits {
			if exit.Default {
				defaults = append(defaults, exit.Tag)
			}
		}
		if len(defaults) != 1 || defaults[0] != tc.want {
			t.Fatalf("default exits = %v, want %q", defaults, tc.want)
		}
	}
}

func TestSelectorMemberOverride(t *testing.T) {
	source := strings.Replace(lifecycleFixture, "rules:", `  - name: other-node
    type: trojan
    server: 127.0.0.1
    port: 9
    password: offline-fixture
proxy-groups:
  - name: group
    type: select
    proxies: [offline-node, other-node]
rules:`, 1)
	req := request{YAML: source, Port: 17890, Exit: "group", Group: "group", Member: "other-node"}
	config, _, err := configuration(req)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Outbounds []struct {
			Tag     string
			Default string
		}
	}
	if err := json.Unmarshal(config, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Outbounds) != 3 || decoded.Outbounds[2].Tag != "group" || decoded.Outbounds[2].Default != "other-node" {
		t.Fatal("group member override did not reach the runtime configuration")
	}
	req.Member = "unknown"
	if _, _, err := configuration(req); err == nil {
		t.Fatal("unknown group member accepted")
	}
}

func TestTunnelConfigurationReplacesListener(t *testing.T) {
	type tunnelConfig struct {
		Inbounds []struct {
			Type      string
			Stack     string
			AutoRoute bool `json:"auto_route"`
		}
		Route struct {
			Final    string
			Detect   bool   `json:"auto_detect_interface"`
			Resolver string `json:"default_domain_resolver"`
		}
		DNS struct {
			Final   string
			Servers []struct {
				Tag, Type, Server, Detour string
				PreferGo                  bool `json:"prefer_go"`
			}
		}
	}
	input := []byte(`{"route":{"final":"selected"},"inbounds":[{"type":"mixed","listen":"127.0.0.1"}]}`)
	for _, tc := range []struct{ resolver, nodeType, nodeServer, appServer string }{
		{"", "local", "", "1.1.1.1"},
		{"system", "local", "", "1.1.1.1"},
		{"ali", "https", "223.5.5.5", "223.5.5.5"},
		{"cloudflare", "https", "1.1.1.1", "1.1.1.1"},
	} {
		t.Run(tc.resolver, func(t *testing.T) {
			var config tunnelConfig
			encoded, err := tunnelConfiguration(input, tc.resolver)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(encoded, &config); err != nil {
				t.Fatal(err)
			}
			if len(config.Inbounds) != 1 || config.Inbounds[0].Type != "tun" ||
				config.Inbounds[0].Stack != "gvisor" || !config.Inbounds[0].AutoRoute ||
				!config.Route.Detect || config.Route.Final != "selected" {
				t.Fatal("TUN mode must replace the local proxy and preserve the selected exit")
			}
			if len(config.DNS.Servers) != 2 || config.Route.Resolver != "node-bootstrap" ||
				config.DNS.Final != "tunnel-dns" {
				t.Fatal("missing distinct node and application DNS paths")
			}
			node, app := config.DNS.Servers[0], config.DNS.Servers[1]
			if node.Tag != "node-bootstrap" || node.Detour != "" || node.Type != tc.nodeType ||
				node.Server != tc.nodeServer || node.PreferGo != (tc.nodeType == "local") ||
				app.Tag != "tunnel-dns" || app.Type != "https" ||
				app.Detour != "selected" || app.Server != tc.appServer {
				t.Fatal("incorrect resolver or detour for node and application DNS")
			}
		})
	}
}

type testTransport func(*http.Request) (*http.Response, error)

func (fn testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func TestSubscriptionResponseLimits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"valid", 200, "\ufeffproxies: []", ""},
		{"redirect", 302, "", "invalid_subscription_response"},
		{"oversized streaming response", 200, strings.Repeat("x", (1<<20)+1), "invalid_subscription_size"},
		{"invalid UTF-8", 200, "\xff", "invalid_subscription_encoding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			body, err := downloadProfileWithTransport("https://example.invalid/sub", testTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{
					StatusCode:    tc.status,
					ContentLength: -1,
					Header:        http.Header{"Location": []string{"https://redirect.invalid/"}},
					Body:          io.NopCloser(strings.NewReader(tc.body)),
				}, nil
			}))
			if calls != 1 {
				t.Fatalf("expected exactly one request, got %d", calls)
			}
			if tc.want == "" {
				if err != nil || body != "proxies: []" {
					t.Fatalf("valid subscription body was not returned: %q, %v", body, err)
				}
			} else if err == nil || err.Error() != tc.want || body != "" {
				t.Fatalf("expected %s and no body, got %v", tc.want, err)
			}
		})
	}
}

func TestProbeSamples(t *testing.T) {
	for _, tc := range []struct {
		host  string
		body  string
		speed bool
		want  bool
	}{
		{"www.apple.com", "Success", false, true},
		{"www.apple.com", "unrelated response", false, false},
		{"speed.cloudflare.com", strings.Repeat("x", sampleBytes), true, true},
		{"speed.cloudflare.com", strings.Repeat("x", sampleBytes+1), true, false},
	} {
		client := &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Scheme != "https" || r.URL.Hostname() != tc.host {
				t.Fatal("unexpected probe destination")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})}
		got := measure(context.Background(), client, tc.speed)
		if got.OK != tc.want || (tc.speed && tc.want && got.MBps <= 0) {
			t.Fatalf("unexpected sample measurement: %+v", got)
		}
	}
}

func TestRejectInvalidSubscriptionURL(t *testing.T) {
	for _, address := range []string{
		"http://example.invalid/",
		"https://user:password@example.invalid/",
		"https://example.invalid/#token",
		"https:///missing-host",
	} {
		if _, err := downloadProfile(address); err == nil || err.Error() != "invalid_subscription_url" {
			t.Errorf("expected URL validation error for %q, got %v", address, err)
		}
	}
}
