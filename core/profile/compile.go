// Package profile converts the supported Clash subset into the prototype envelope.
package profile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const MaxBytes = 1 << 20

type Envelope struct {
	CoreJSON   string   `json:"coreJSON"`
	DNSServers []string `json:"dnsServers"`
}
type Report struct {
	CoreValidated        bool     `json:"coreValidated"`
	Nodes                int      `json:"nodes"`
	VLESS                int      `json:"vless"`
	Trojan               int      `json:"trojan"`
	Groups               int      `json:"groups"`
	DisabledGroupChoices int      `json:"disabledGroupChoices"`
	IgnoredRules         int      `json:"ignoredRules"`
	StaticDirectCIDRs    int      `json:"staticDirectCIDRs"`
	Notices              []string `json:"notices"`
}
type node struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	Server      string `yaml:"server"`
	Port        uint16 `yaml:"port"`
	UUID        string `yaml:"uuid"`
	Password    string `yaml:"password"`
	TLS         bool   `yaml:"tls"`
	UDP         bool   `yaml:"udp"`
	Flow        string `yaml:"flow"`
	Network     string `yaml:"network"`
	SNI         string `yaml:"sni"`
	Servername  string `yaml:"servername"`
	Fingerprint string `yaml:"client-fingerprint"`
	SkipVerify  bool   `yaml:"skip-cert-verify"`
	Reality     struct {
		PublicKey string `yaml:"public-key"`
		ShortID   string `yaml:"short-id"`
	} `yaml:"reality-opts"`
}
type group struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Proxies []string `yaml:"proxies"`
}
type clash struct {
	Proxies []node   `yaml:"proxies"`
	Groups  []group  `yaml:"proxy-groups"`
	Rules   []string `yaml:"rules"`
	DNS     struct {
		Nameserver []string `yaml:"nameserver"`
		Default    []string `yaml:"default-nameserver"`
	} `yaml:"dns"`
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func failure(code string) error { return errors.New(code) }
func reserved(name string) bool {
	return name == "DIRECT" || name == "REJECT" || name == "REJECT-DROP" || name == "PASS"
}

// Compile never downloads providers or contacts node servers. Error strings and
// Report intentionally omit names, endpoints, subscription URLs and credentials.
func Compile(data []byte, dnsOverride []string) (Envelope, Report, error) {
	var result Envelope
	report := Report{Notices: []string{"prototype_global_only", "system_dns_replaces_clash_dns", "desktop_tun_and_controller_disabled", "remote_rule_providers_not_downloaded"}}
	if len(data) == 0 || len(data) > MaxBytes {
		return result, report, failure("invalid_configuration_size")
	}
	var source clash
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&source); err != nil {
		return result, report, failure("invalid_yaml")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return result, report, failure("multiple_yaml_documents_not_supported")
	}
	// Unknown transport/authentication fields must not be silently discarded.
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return result, report, failure("invalid_yaml")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return result, report, failure("invalid_yaml_root")
	}
	root := document.Content[0]
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value != "proxies" {
			continue
		}
		sequence := root.Content[i+1]
		if sequence.Kind != yaml.SequenceNode {
			return result, report, failure("invalid_node_list")
		}
		for _, entry := range sequence.Content {
			encoded, err := yaml.Marshal(entry)
			if err != nil {
				return result, report, failure("invalid_node")
			}
			single := yaml.NewDecoder(bytes.NewReader(encoded))
			single.KnownFields(true)
			var checked node
			if err = single.Decode(&checked); err != nil {
				return result, report, failure("unsupported_node_field")
			}
		}
	}
	if len(source.Proxies) == 0 || len(source.Proxies) > 2048 || len(source.Groups) > 128 {
		return result, report, failure("invalid_node_or_group_count")
	}
	known := map[string]bool{}
	for _, n := range source.Proxies {
		if n.Name == "" || known[n.Name] || reserved(n.Name) {
			return result, report, failure("duplicate_or_invalid_name")
		}
		known[n.Name] = true
	}
	for _, g := range source.Groups {
		if g.Name == "" || known[g.Name] || reserved(g.Name) {
			return result, report, failure("duplicate_or_invalid_name")
		}
		known[g.Name] = true
	}
	outbounds := []any{}
	for _, n := range source.Proxies {
		if n.Server == "" || strings.TrimSpace(n.Server) != n.Server || n.Port == 0 || n.SkipVerify || (n.Network != "" && n.Network != "tcp") {
			return result, report, failure("unsupported_node_parameters")
		}
		hostname := n.Servername
		if hostname == "" {
			hostname = n.SNI
		}
		if hostname == "" {
			hostname = n.Server
		}
		tls := map[string]any{"enabled": true, "server_name": hostname}
		outbound := map[string]any{"type": n.Type, "tag": n.Name, "server": n.Server, "server_port": n.Port, "tls": tls}
		if !n.UDP {
			outbound["network"] = "tcp"
		}
		switch n.Type {
		case "vless":
			if !uuidPattern.MatchString(n.UUID) || !n.TLS || (n.Flow != "" && n.Flow != "xtls-rprx-vision") {
				return result, report, failure("invalid_vless_parameters")
			}
			outbound["uuid"] = n.UUID
			if n.Flow != "" {
				outbound["flow"] = n.Flow
			}
			if n.Reality.PublicKey != "" {
				key, err := base64.RawURLEncoding.DecodeString(n.Reality.PublicKey)
				if err != nil || len(key) != 32 {
					return result, report, failure("invalid_reality_public_key")
				}
				short := n.Reality.ShortID
				if len(short) > 16 || len(short)%2 != 0 || strings.Trim(short, "0123456789abcdefABCDEF") != "" {
					return result, report, failure("invalid_reality_short_id")
				}
				tls["reality"] = map[string]any{"enabled": true, "public_key": n.Reality.PublicKey, "short_id": short}
			}
			report.VLESS++
		case "trojan":
			if n.Password == "" {
				return result, report, failure("missing_trojan_password")
			}
			outbound["password"] = n.Password
			report.Trojan++
		default:
			return result, report, failure("unsupported_node_protocol")
		}
		if n.Fingerprint != "" {
			switch n.Fingerprint {
			case "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized":
			default:
				return result, report, failure("unsupported_tls_fingerprint")
			}
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": n.Fingerprint}
		}
		outbounds = append(outbounds, outbound)
	}
	graph := map[string][]string{}
	for _, g := range source.Groups {
		if g.Type != "select" {
			return result, report, failure("unsupported_group_type")
		}
		members := []string{}
		for _, member := range g.Proxies {
			if reserved(member) {
				report.DisabledGroupChoices++
				continue
			}
			if !known[member] {
				return result, report, failure("unknown_group_reference")
			}
			members = append(members, member)
		}
		if len(members) == 0 {
			return result, report, failure("empty_proxy_group")
		}
		graph[g.Name] = members
		outbounds = append(outbounds, map[string]any{"type": "selector", "tag": g.Name, "outbounds": members, "default": members[0]})
	}
	colors := map[string]int{}
	var visit func(string) bool
	visit = func(name string) bool {
		if colors[name] == 1 {
			return false
		}
		if colors[name] == 2 {
			return true
		}
		colors[name] = 1
		for _, member := range graph[name] {
			if !visit(member) {
				return false
			}
		}
		colors[name] = 2
		return true
	}
	for name := range graph {
		if !visit(name) {
			return result, report, failure("cyclic_group_reference")
		}
	}
	final := source.Proxies[0].Name
	if len(source.Groups) > 0 {
		final = source.Groups[0].Name
	}
	matched := false
	for _, rule := range source.Rules {
		fields := strings.Split(rule, ",")
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		if fields[0] == "MATCH" {
			if len(fields) != 2 || !known[fields[1]] || matched {
				return result, report, failure("invalid_default_route")
			}
			final = fields[1]
			matched = true
			continue
		}
		report.IgnoredRules++
		if len(fields) >= 3 && (fields[0] == "IP-CIDR" || fields[0] == "IP-CIDR6") && fields[2] == "DIRECT" {
			if _, err := netip.ParsePrefix(fields[1]); err != nil {
				return result, report, failure("invalid_direct_cidr")
			}
			report.StaticDirectCIDRs++
		}
	}
	candidates := dnsOverride
	if len(candidates) == 0 {
		candidates = append(append([]string{}, source.DNS.Nameserver...), source.DNS.Default...)
	}
	seenDNS := map[string]bool{}
	for _, candidate := range candidates {
		if ip, err := netip.ParseAddr(candidate); err == nil && !seenDNS[ip.String()] {
			result.DNSServers = append(result.DNSServers, ip.String())
			seenDNS[ip.String()] = true
			if len(result.DNSServers) == 4 {
				break
			}
		} else if len(dnsOverride) > 0 && err != nil {
			return result, report, failure("invalid_dns_override")
		}
	}
	if len(result.DNSServers) == 0 {
		return result, report, failure("explicit_dns_ip_required")
	}
	config := map[string]any{
		"log":       map[string]any{"disabled": true},
		"inbounds":  []any{map[string]any{"type": "tun", "tag": "packetflow", "address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}, "mtu": 1400, "stack": "gvisor", "dns_mode": "disabled", "auto_route": false}},
		"outbounds": outbounds, "route": map[string]any{"final": final},
	}
	raw, err := json.Marshal(config)
	if err != nil {
		return result, report, failure("configuration_encoding_failed")
	}
	result.CoreJSON = string(raw)
	report.Nodes = len(source.Proxies)
	report.Groups = len(source.Groups)
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > MaxBytes {
		return Envelope{}, report, failure("compiled_configuration_too_large")
	}
	return result, report, nil
}
