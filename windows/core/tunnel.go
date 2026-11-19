package main

import (
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
)

const (
	tunnelIPv4CIDR = "172.29.255.1/30"
	tunnelIPv6CIDR = "fdfe:29:255::1/126"
)

// Input comes only from configuration, which rebuilds the subscription using
// the shared allowlist. The caller never supplies interface or routing fields.
func tunnelConfiguration(config []byte, resolver string) ([]byte, error) {
	var root map[string]any
	if err := json.Unmarshal(config, &root); err != nil {
		return nil, err
	}
	route, ok := root["route"].(map[string]any)
	if !ok {
		return nil, errors.New("missing_tunnel_route")
	}
	route["auto_detect_interface"] = true
	route["default_domain_resolver"] = "node-bootstrap"
	route["rules"] = []any{map[string]any{"port": 53, "action": "hijack-dns"}}
	root["inbounds"] = []any{map[string]any{
		"type": "tun", "tag": "windows-tun", "interface_name": "ALiangProxy",
		"address": []string{tunnelIPv4CIDR, tunnelIPv6CIDR},
		// Avoid the system stack's local TCP forwarder and firewall rule on Windows.
		"mtu": 1400, "stack": "gvisor", "auto_route": true, "dns_mode": "hijack",
	}}
	useSystemDNS := resolver == "" || resolver == "system"
	if useSystemDNS {
		resolver = "cloudflare"
	}
	business, err := bootstrapResolver(resolver)
	if err != nil {
		return nil, err
	}
	// Resolve the node over the underlying interface before using it for app DNS.
	bootstrap := maps.Clone(business)
	if useSystemDNS {
		bootstrap = map[string]any{"type": "local", "tag": "node-bootstrap", "prefer_go": true}
	}
	business["tag"] = "tunnel-dns"
	business["detour"] = route["final"]
	root["dns"] = map[string]any{"servers": []any{bootstrap, business}, "final": "tunnel-dns"}
	return json.Marshal(root)
}

func tunnelDNSProbeAddresses() (source, server netip.Addr) {
	source = netip.MustParsePrefix(tunnelIPv4CIDR).Addr()
	// sing-tun assigns the next address as the virtual DNS server.
	return source, source.Next()
}

func bootstrapResolver(resolver string) (map[string]any, error) {
	var ip, serverName string
	switch resolver {
	case "cloudflare":
		ip, serverName = "1.1.1.1", "cloudflare-dns.com"
	case "ali":
		ip, serverName = "223.5.5.5", "dns.alidns.com"
	default:
		return nil, errors.New("unsupported_resolver")
	}
	return map[string]any{
		"type": "https", "tag": "node-bootstrap", "server": ip, "server_port": 443,
		"path": "/dns-query", "tls": map[string]any{"enabled": true, "server_name": serverName},
	}, nil
}
