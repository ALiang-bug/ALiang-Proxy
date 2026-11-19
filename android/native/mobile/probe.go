package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	sj "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type probeResult struct {
	OK      bool    `json:"ok"`
	Error   string  `json:"error,omitempty"`
	DelayMS int64   `json:"delayMS,omitempty"`
	Bytes   int64   `json:"bytes,omitempty"`
	MBps    float64 `json:"MBps,omitempty"`
}

// Probe has fixed HTTPS targets, no public listener, no redirects and no direct
// fallback. Call only while the application's VPN is stopped.
func Probe(source, selected, resolver string, speed bool) (string, error) {
	return runProbe(context.Background(), source, selected, resolver, speed)
}

// ProbeJob is single-use and cancellable across JNI. Creating it performs no IO.
type ProbeJob struct {
	mu                         sync.Mutex
	source, selected, resolver string
	speed, started             bool
	ctx                        context.Context
	cancel                     context.CancelFunc
}

func NewProbeJob(source, selected, resolver string, speed bool) (*ProbeJob, error) {
	if len(source) > 1<<20 || len(selected) > 512 {
		return nil, errors.New("configuration_too_large")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &ProbeJob{source: source, selected: selected, resolver: resolver, speed: speed, ctx: ctx, cancel: cancel}, nil
}
func (p *ProbeJob) Cancel() {
	if p != nil && p.cancel != nil {
		p.cancel()
	}
}
func (p *ProbeJob) Run() (string, error) {
	p.mu.Lock()
	if p.ctx == nil || p.cancel == nil {
		p.mu.Unlock()
		return "", errors.New("probe_uninitialized")
	}
	if p.started {
		p.mu.Unlock()
		return "", errors.New("probe_already_started")
	}
	p.started = true
	source, selected, resolver, speed := p.source, p.selected, p.resolver, p.speed
	p.source = ""
	p.selected = ""
	p.resolver = ""
	p.mu.Unlock()
	defer p.cancel()
	if p.ctx.Err() != nil {
		return `{"ok":false,"error":"cancelled"}`, nil
	}
	return runProbe(p.ctx, source, selected, resolver, speed)
}

func runProbe(parent context.Context, source, selected, resolver string, speed bool) (string, error) {
	data, info, err := compiled(source, selected, "{}", resolver)
	if err != nil {
		return "", errors.New("invalid_core_configuration")
	}
	found := false
	for _, tag := range info.Nodes {
		if tag == selected {
			found = true
		}
	}
	if !found {
		return "", errors.New("leaf_node_required")
	}
	ctx, cancel := context.WithTimeout(coreContext(), 20*time.Second)
	stopParent := context.AfterFunc(parent, cancel)
	defer stopParent()
	if parent.Err() != nil {
		cancel()
		return `{"ok":false,"error":"cancelled"}`, nil
	}
	defer cancel()
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, &androidPlatform{fd: -1, protector: probeProtector{}})
	options, err := sj.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		return "", errors.New("invalid_core_configuration")
	}
	options.Inbounds = nil
	options.Route.Rules = nil
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	result := probeResult{Error: "initialization_failed"}
	if err == nil {
		defer instance.Close()
		if instance.Start() == nil {
			transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return instance.Outbound().Default().DialContext(ctx, network, M.ParseSocksaddr(address))
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
			target := "https://www.apple.com/library/test/success.html"
			if speed {
				target = "https://speed.cloudflare.com/__down?bytes=5242880"
			}
			result = measure(ctx, client, target, speed)
		} else {
			result.Error = "startup_failed"
		}
	}
	encoded, _ := json.Marshal(result)
	return string(encoded), nil
}

// Probe has no TUN and is invoked only after the UI rejects any active VPN.
type probeProtector struct{}

func (probeProtector) Protect(int32) bool { return true }

func measure(ctx context.Context, client *http.Client, target string, speed bool) probeResult {
	started := time.Now()
	request, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return probeResult{Error: "request_failed"}
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-cache")
	response, err := client.Do(request)
	if err != nil {
		return probeResult{Error: "connection_or_tls_failed"}
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return probeResult{Error: "unexpected_http_status"}
	}
	delay := time.Since(started).Milliseconds()
	if !speed {
		body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
		if err != nil || len(body) > 4096 || !strings.Contains(string(body), "Success") {
			return probeResult{Error: "invalid_response"}
		}
		return probeResult{OK: true, DelayMS: delay}
	}
	const limit = 5 * 1024 * 1024
	n, err := io.Copy(io.Discard, io.LimitReader(response.Body, limit+1))
	if err != nil || n != limit {
		return probeResult{Error: "incomplete_download", Bytes: n}
	}
	return probeResult{OK: true, DelayMS: delay, Bytes: n, MBps: float64(n) / 1e6 / time.Since(started).Seconds()}
}
