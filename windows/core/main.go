package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/experimental/privateprofile"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	sjson "github.com/sagernet/sing/common/json"
)

type request struct {
	YAML     string
	Exit     string
	Port     uint16
	URL      string
	Speed    bool
	Group    string
	Member   string
	Resolver string
}

func downloadProfile(address string) (string, error) {
	return downloadProfileWithTransport(address, &http.Transport{DisableCompression: true})
}

func downloadProfileWithTransport(address string, transport http.RoundTripper) (string, error) {
	u, err := url.Parse(address)
	if err != nil || len(address) > 8192 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return "", errors.New("invalid_subscription_url")
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Clash/ALiang-Proxy")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > privateprofile.MaxBytes {
		return "", errors.New("invalid_subscription_response")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, privateprofile.MaxBytes+1))
	if err != nil || len(data) > privateprofile.MaxBytes {
		return "", errors.New("invalid_subscription_size")
	}
	if !utf8.Valid(data) {
		return "", errors.New("invalid_subscription_encoding")
	}
	return strings.TrimPrefix(string(data), "\ufeff"), nil
}

type outboundSummary struct {
	Tag     string   `json:"tag"`
	Type    string   `json:"type"`
	Members []string `json:"outbounds,omitempty"`
	Default bool     `json:"defaultExit,omitempty"`
}

func validDisplayTag(tag string) bool {
	if tag == "" || len(tag) > 512 {
		return false
	}
	for _, r := range tag {
		if unicode.IsControl(r) || r == '\u061c' || r == '\u200e' || r == '\u200f' ||
			(r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069') {
			return false
		}
	}
	return true
}

func configuration(req request) ([]byte, []outboundSummary, error) {
	if req.Port < 1025 || len(req.YAML) > privateprofile.MaxBytes {
		return nil, nil, errors.New("invalid_input")
	}
	envelope, _, err := privateprofile.Compile([]byte(req.YAML), []string{"1.1.1.1"})
	if err != nil {
		return nil, nil, errors.New("invalid_subscription")
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal([]byte(envelope.CoreJSON), &cfg); err != nil {
		return nil, nil, err
	}
	var exits []outboundSummary
	if err := json.Unmarshal(cfg["outbounds"], &exits); err != nil {
		return nil, nil, err
	}
	for _, exit := range exits {
		if !validDisplayTag(exit.Tag) {
			return nil, nil, errors.New("invalid_display_name")
		}
	}
	if req.Group != "" || req.Member != "" {
		var outbounds []map[string]json.RawMessage
		if err := json.Unmarshal(cfg["outbounds"], &outbounds); err != nil {
			return nil, nil, err
		}
		matched := false
		for i, exit := range exits {
			if exit.Type != "selector" || exit.Tag != req.Group {
				continue
			}
			for _, member := range exit.Members {
				if member == req.Member {
					outbounds[i]["default"], _ = json.Marshal(member)
					matched = true
					break
				}
			}
		}
		if !matched {
			return nil, nil, errors.New("unknown_group_member")
		}
		cfg["outbounds"], _ = json.Marshal(outbounds)
	}
	if req.Exit != "" {
		valid := false
		for _, exit := range exits {
			valid = valid || exit.Tag == req.Exit
		}
		if !valid {
			return nil, nil, errors.New("unknown_exit")
		}
		cfg["route"], _ = json.Marshal(map[string]string{"final": req.Exit})
	}
	var route struct{ Final string }
	if err := json.Unmarshal(cfg["route"], &route); err != nil {
		return nil, nil, err
	}
	for i := range exits {
		exits[i].Default = exits[i].Tag == route.Final
	}
	if req.Resolver != "" && req.Resolver != "system" {
		resolver, err := bootstrapResolver(req.Resolver)
		if err != nil {
			return nil, nil, err
		}
		cfg["route"], _ = json.Marshal(map[string]string{
			"final": route.Final, "default_domain_resolver": "node-bootstrap",
		})
		cfg["dns"], _ = json.Marshal(map[string]any{
			"servers": []any{resolver}, "final": "node-bootstrap",
		})
	}
	cfg["inbounds"], _ = json.Marshal([]map[string]any{{
		"type": "mixed", "listen": "127.0.0.1", "listen_port": req.Port,
	}})
	encoded, err := json.Marshal(cfg)
	return encoded, exits, err
}

var errCoreCleanup = errors.New("windows_core_cleanup_failed")

func run() (runErr error) {
	if len(os.Args) != 2 {
		return errors.New("unknown_command")
	}
	switch os.Args[1] {
	case "check-tun":
		return json.NewEncoder(os.Stdout).Encode(checkTunnelInternet(context.Background()))
	case "inspect", "run", "download", "probe", "tun":
	default:
		return errors.New("unknown_command")
	}
	// JSON is one line. Holding stdin open keeps the child alive; closing it stops the proxy.
	input := bufio.NewReader(io.LimitReader(os.Stdin, 7*privateprofile.MaxBytes))
	frame, err := input.ReadBytes('\n')
	if err != nil {
		return errors.New("invalid_request_frame")
	}
	var req request
	decoder := json.NewDecoder(strings.NewReader(string(frame)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid_request")
	}
	if os.Args[1] == "download" {
		source, err := downloadProfile(req.URL)
		if err != nil {
			return err
		}
		req.YAML = source
		if _, _, err := configuration(req); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"yaml": source})
	}
	config, exits, err := configuration(req)
	if err != nil {
		return err
	}
	if os.Args[1] == "inspect" {
		return json.NewEncoder(os.Stdout).Encode(exits)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	go func() {
		_, _ = io.Copy(io.Discard, input)
		cancel()
	}()
	if os.Args[1] == "probe" {
		return probe(ctx, config, exits, req)
	}
	if os.Args[1] == "tun" {
		if err := checkTunnelAccess(); err != nil {
			return err
		}
		config, err = tunnelConfiguration(config, req.Resolver)
		if err != nil {
			return err
		}
	}
	instance, err := newCore(ctx, config)
	if err != nil {
		return err
	}
	defer func() {
		if instance.Close() != nil {
			runErr = errors.Join(runErr, errCoreCleanup)
		}
	}()
	if err := json.NewEncoder(os.Stdout).Encode(map[string]bool{"ready": true}); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

func newCore(ctx context.Context, config []byte) (*box.Box, error) {
	in := inbound.NewRegistry()
	mixed.RegisterInbound(in)
	tun.RegisterInbound(in)
	out := outbound.NewRegistry()
	vless.RegisterOutbound(out)
	trojan.RegisterOutbound(out)
	group.RegisterSelector(out)
	resolvers := dns.NewTransportRegistry()
	local.RegisterTransport(resolvers)
	transport.RegisterHTTPS(resolvers)
	ctx = box.Context(ctx, in, out, endpoint.NewRegistry(), resolvers,
		service.NewRegistry(), certificate.NewRegistry())
	options, err := sjson.UnmarshalExtendedContext[option.Options](ctx, config)
	if err != nil {
		return nil, err
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return nil, err
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		return nil, err
	}
	return instance, nil
}

func main() {
	if err := run(); err != nil {
		// Runtime errors can contain subscription data.
		code := "windows_core_failed"
		if errors.Is(err, errCoreCleanup) {
			code = errCoreCleanup.Error()
		}
		_, _ = os.Stderr.WriteString(code + "\n")
		os.Exit(1)
	}
}
