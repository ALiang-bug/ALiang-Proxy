// Package mobile is the narrow JNI boundary. Imported YAML never becomes a raw
// sing-box configuration accepted from Java. Runtime configuration is rebuilt.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"runtime/debug"
	"sync"
	"syscall"
	"unicode"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"privateproxy/core/profile"
)

func init() { debug.SetMemoryLimit(192 << 20) }

// Protector must reject sockets that Android cannot exempt from the tunnel.
type Protector interface{ Protect(fd int32) bool }

type summary struct {
	Nodes   []string            `json:"nodes"`
	Groups  map[string][]string `json:"groups"`
	Default string              `json:"default"`
	Notices []string            `json:"notices"`
}

func compiled(source, selected, choices, resolver string) ([]byte, summary, error) {
	var info summary
	if len(source) > profile.MaxBytes || len(choices) > 65536 {
		return nil, info, errors.New("configuration_too_large")
	}
	envelope, report, err := profile.Compile([]byte(source), []string{"223.5.5.5"})
	if err != nil {
		return nil, info, err
	}
	var config map[string]any
	if json.Unmarshal([]byte(envelope.CoreJSON), &config) != nil {
		return nil, info, errors.New("invalid_configuration")
	}
	info.Groups = map[string][]string{}
	info.Notices = append(report.Notices, "android_global_tunnel", "domain_and_ip_rules_disabled")
	var selection map[string]string
	if choices != "" && json.Unmarshal([]byte(choices), &selection) != nil {
		return nil, info, errors.New("invalid_selection")
	}
	known := map[string]bool{}
	outs := config["outbounds"].([]any)
	for _, entry := range outs {
		out := entry.(map[string]any)
		tag := out["tag"].(string)
		// Subscription-controlled labels are rendered by Android. Bound their
		// layout cost and reject control characters that can disguise choices.
		if len(tag) > 512 || stringsContainsUnsafeLabel(tag) {
			return nil, info, errors.New("invalid_display_name")
		}
		if host, ok := out["server"].(string); ok && len(host) > 253 {
			return nil, info, errors.New("invalid_server_length")
		}
		known[tag] = true
		if out["type"] == "selector" {
			members := out["outbounds"].([]any)
			for _, m := range members {
				info.Groups[tag] = append(info.Groups[tag], m.(string))
			}
			if value, ok := selection[tag]; ok {
				found := false
				for _, m := range members {
					if m == value {
						found = true
					}
				}
				if !found {
					return nil, info, errors.New("invalid_group_selection")
				}
				out["default"] = value
			}
		} else {
			info.Nodes = append(info.Nodes, tag)
		}
	}
	for tag := range selection {
		if _, ok := info.Groups[tag]; !ok {
			return nil, info, errors.New("unknown_group")
		}
	}
	route := config["route"].(map[string]any)
	// sing-box only installs the platform socket-protection Control callback
	// when interface detection is enabled. Without it, the node's own socket
	// re-enters the Android TUN and recursively proxies itself.
	route["auto_detect_interface"] = true
	info.Default = route["final"].(string)
	if selected != "" {
		if !known[selected] {
			return nil, info, errors.New("unknown_exit")
		}
		route["final"] = selected
	}
	address, hostname := "223.5.5.5", "dns.alidns.com"
	switch resolver {
	case "ali":
	case "cloudflare":
		address, hostname = "1.1.1.1", "cloudflare-dns.com"
	default:
		return nil, info, errors.New("invalid_resolver")
	}
	bootstrap := map[string]any{"type": "https", "tag": "bootstrap", "server": address, "server_port": 443, "path": "/dns-query", "tls": map[string]any{"enabled": true, "server_name": hostname}}
	business := map[string]any{}
	for k, v := range bootstrap {
		business[k] = v
	}
	business["tag"] = "business"
	business["detour"] = route["final"]
	config["dns"] = map[string]any{"servers": []any{bootstrap, business}, "final": "business", "strategy": "prefer_ipv4"}
	route["default_domain_resolver"] = "bootstrap"
	route["rules"] = []any{map[string]any{"port": 53, "action": "hijack-dns"}}
	config["inbounds"] = []any{map[string]any{"type": "tun", "tag": "android-tun", "address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}, "mtu": 1400, "stack": "gvisor", "auto_route": false, "dns_mode": "disabled"}}
	data, err := json.Marshal(config)
	return data, info, err
}

func stringsContainsUnsafeLabel(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) || (r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069') {
			return true
		}
	}
	return false
}

func Inspect(source string) (string, error) {
	_, info, err := compiled(source, "", "", "ali")
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(info)
	return string(data), err
}

type Session struct {
	mu       sync.Mutex
	instance *box.Box
	cancel   context.CancelFunc
	closed   bool
}

// FD is borrowed from Android; the Go TUN owns only a dup. Java retains the
// original descriptor so emergency stop can release its side independently.
func Start(source, selected, choices, resolver string, fd int32, protector Protector) (*Session, error) {
	if fd < 0 || protector == nil {
		return nil, errors.New("missing_tunnel")
	}
	data, _, err := compiled(source, selected, choices, resolver)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(coreContext())
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, &androidPlatform{fd: int(fd), protector: protector})
	options, err := sjson.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		cancel()
		return nil, errors.New("invalid_core_configuration")
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		return nil, errors.New("core_initialization_failed")
	}
	if err = instance.Start(); err != nil {
		cancel()
		instance.Close()
		return nil, errors.New("core_start_failed")
	}
	return &Session{instance: instance, cancel: cancel}, nil
}
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.cancel()
	if s.instance.Close() != nil {
		return errors.New("core_stop_failed")
	}
	return nil
}
func Version() string { return "sing-box 1.14.4 / ALiang Android 0.1" }

type androidPlatform struct {
	platformInterfaceStub
	fd        int
	protector Protector
}

func (p *androidPlatform) UsePlatformInterface() bool { return true }

// Android protects each socket via VpnService. Do not open an unprivileged
// netlink route monitor; it is prohibited on recent Android versions.
func (p *androidPlatform) UsePlatformDefaultInterfaceMonitor() bool    { return true }
func (p *androidPlatform) UsePlatformAutoDetectInterfaceControl() bool { return true }
func (p *androidPlatform) AutoDetectInterfaceControl(fd int) error {
	if !p.protector.Protect(int32(fd)) {
		return errors.New("socket_protection_failed")
	}
	return nil
}
func (p *androidPlatform) MyInterfaceAddress() []netip.Addr {
	return []netip.Addr{netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("fdfe:dcba:9876::1")}
}
func (p *androidPlatform) OpenInterface(options *tun.Options, _ option.TunPlatformOptions) (tun.Tun, error) {
	fd, err := syscall.Dup(p.fd)
	if err != nil {
		return nil, errors.New("tunnel_dup_failed")
	}
	syscall.CloseOnExec(fd)
	options.FileDescriptor = fd
	// VpnService.Builder owns interface addresses, DNS and routes. The native
	// stack must never attempt root-only netlink configuration or cleanup.
	options.EXP_ExternalConfiguration = true
	options.Name = fmt.Sprintf("aliang-%d", p.fd)
	device, err := tun.New(*options)
	if err != nil {
		syscall.Close(fd)
		return nil, errors.New("tunnel_open_failed")
	}
	return device, nil
}
