package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
)

const sampleBytes = 5 * 1024 * 1024
const latencyHost = "www.apple.com"

type tunnelCheck struct {
	DNS       bool `json:"dns"`
	HTTPS     bool `json:"https"`
	TunnelDNS bool `json:"tunnelDns"`
}

func checkTunnelInternet(ctx context.Context) tunnelCheck {
	lookupCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	addresses, err := net.DefaultResolver.LookupHost(lookupCtx, latencyHost)
	cancel()
	if err != nil || len(addresses) == 0 {
		source, server := tunnelDNSProbeAddresses()
		return tunnelCheck{TunnelDNS: checkTunnelDNS(ctx, source, netip.AddrPortFrom(server, 53), latencyHost)}
	}
	// Use normal OS routing and skip any HTTP proxy settings.
	client := &http.Client{
		Transport:     &http.Transport{DisableKeepAlives: true, DisableCompression: true},
		Timeout:       8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return tunnelCheck{DNS: true, HTTPS: measure(ctx, client, false).OK}
}

func checkTunnelDNS(ctx context.Context, source netip.Addr, server netip.AddrPort, host string) bool {
	// Bind to the tunnel IP so the fallback check cannot use the physical adapter.
	client := dns.Client{
		Net:     "udp4",
		Timeout: 5 * time.Second,
		Dialer:  &net.Dialer{LocalAddr: &net.UDPAddr{IP: source.AsSlice()}},
	}
	query := new(dns.Msg).SetQuestion(dns.Fqdn(host), dns.TypeA)
	reply, _, err := client.ExchangeContext(ctx, query, server.String())
	if err != nil || reply.Rcode != dns.RcodeSuccess || !reply.Response {
		return false
	}
	for _, answer := range reply.Answer {
		if answer.Header().Rrtype == dns.TypeA {
			return true
		}
	}
	return false
}

type result struct {
	Tag          string  `json:"tag"`
	OK           bool    `json:"ok"`
	Milliseconds int64   `json:"ms"`
	MBps         float64 `json:"mbps"`
}

func probe(ctx context.Context, config []byte, exits []outboundSummary, req request) error {
	var options map[string]json.RawMessage
	if err := json.Unmarshal(config, &options); err != nil {
		return err
	}
	delete(options, "inbounds")
	safe, err := json.Marshal(options)
	if err != nil {
		return err
	}
	instance, err := newCore(ctx, safe)
	if err != nil {
		return err
	}
	defer instance.Close()
	encoder := json.NewEncoder(os.Stdout)
	for _, exit := range exits {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if exit.Type == "selector" || (req.Exit != "" && exit.Tag != req.Exit) {
			continue
		}
		out, ok := instance.Outbound().Outbound(exit.Tag)
		if !ok {
			return errors.New("probe_outbound_missing")
		}
		transport := &http.Transport{
			DisableKeepAlives: true, DisableCompression: true,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return out.DialContext(ctx, network, M.ParseSocksaddr(address))
			},
		}
		c := &http.Client{Transport: transport, Timeout: 12 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		row := measure(ctx, c, req.Speed)
		row.Tag = exit.Tag
		transport.CloseIdleConnections()
		if err := encoder.Encode(row); err != nil {
			return err
		}
	}
	return encoder.Encode(map[string]bool{"done": true})
}

func measure(ctx context.Context, client *http.Client, speed bool) result {
	target := "https://" + latencyHost + "/library/test/success.html"
	if speed {
		target = "https://speed.cloudflare.com/__down?bytes=5242880"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return result{}
	}
	start := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return result{}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result{}
	}
	latency := time.Since(start).Milliseconds()
	if speed {
		n, err := io.Copy(io.Discard, io.LimitReader(response.Body, sampleBytes+1))
		if err != nil || n != sampleBytes {
			return result{}
		}
		return result{OK: true, Milliseconds: latency, MBps: float64(n) / 1e6 / time.Since(start).Seconds()}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(body) > 4096 || !strings.Contains(string(body), "Success") {
		return result{}
	}
	return result{OK: true, Milliseconds: latency}
}
