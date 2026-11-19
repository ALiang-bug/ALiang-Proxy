// Development-only loopback Reality gateway. Never included in APK.
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/vless"
	sj "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

func main() {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	var connections sync.Map
	defer func() { connections.Range(func(k, v any) bool { k.(net.Conn).Close(); return true }) }()
	handshake, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		panic(err)
	}
	defer handshake.Close()
	go func() {
		for {
			c, e := handshake.Accept()
			if e != nil {
				return
			}
			connections.Store(c, true)
			go func() { defer c.Close(); defer connections.Delete(c); io.Copy(io.Discard, c) }()
		}
	}()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer tcp.Close()
	port := tcp.Addr().(*net.TCPAddr).Port
	go http.Serve(tcp, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.Write([]byte("ALiang offline path OK"))
	}))
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		panic(err)
	}
	defer udp.Close()
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, a, e := udp.ReadFromUDP(buffer)
			if e != nil {
				return
			}
			udp.WriteToUDP(buffer[:n], a)
		}
	}()
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	serverPort := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	reality, _ := ecdh.X25519().GenerateKey(rand.Reader)
	const uuid = "00000000-0000-4000-8000-000000000001"
	users := []any{map[string]any{"uuid": uuid, "flow": "xtls-rprx-vision"}}
	serverTLS := map[string]any{"enabled": true, "server_name": "localhost", "reality": map[string]any{"enabled": true, "private_key": base64.RawURLEncoding.EncodeToString(reality.Bytes()), "short_id": []string{"0123456789abcdef"}, "handshake": map[string]any{"server": "127.0.0.1", "server_port": handshake.Addr().(*net.TCPAddr).Port}}}
	authYAML := fmt.Sprintf("    uuid: %s\n    flow: xtls-rprx-vision\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: %s\n      short-id: '0123456789abcdef'\n", uuid, base64.RawURLEncoding.EncodeToString(reality.PublicKey().Bytes()))
	ctx := gatewayContext()
	optionsJSON, _ := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "vless", "listen": "127.0.0.1", "listen_port": serverPort, "users": users, "tls": serverTLS}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "echo"}}, "route": map[string]any{"final": "echo", "rules": []any{map[string]any{"action": "route", "outbound": "echo", "override_address": "127.0.0.1", "override_port": port}}}})
	// Only this development tool exposes a server or direct outbound.
	inboundRegistry := service.FromContext[adapter.InboundRegistry](ctx)
	outboundRegistry := service.FromContext[adapter.OutboundRegistry](ctx)
	vless.RegisterInbound(inboundRegistry.(*inbound.Registry))

	direct.RegisterOutbound(outboundRegistry.(*outbound.Registry))
	opts, err := sj.UnmarshalExtendedContext[option.Options](ctx, optionsJSON)
	if err != nil {
		panic(err)
	}
	server, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		panic(err)
	}
	defer server.Close()
	if err = server.Start(); err != nil {
		panic(err)
	}

	source := fmt.Sprintf("proxies:\n  - name: test-node\n    type: vless\n    server: 10.0.2.2\n    port: %d\n    tls: true\n    udp: true\n    servername: localhost\n%sproxy-groups:\n  - name: default-group\n    type: select\n    proxies: [test-node]\nrules: ['MATCH,default-group']\n", serverPort, authYAML)
	if len(os.Args) != 2 {
		panic("provide fixture YAML output path")
	}
	if err = os.WriteFile(os.Args[1], []byte(source), 0600); err != nil {
		panic(err)
	}
	fmt.Println("Offline gateway ready; all egress overridden to loopback HTTP/UDP echo.")
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	<-signals
}

func gatewayContext() context.Context {
	in := inbound.NewRegistry()

	out := outbound.NewRegistry()

	resolvers := dns.NewTransportRegistry()
	local.RegisterTransport(resolvers)
	transport.RegisterHTTPS(resolvers)
	return box.Context(context.Background(), in, out, endpoint.NewRegistry(), resolvers, boxservice.NewRegistry(), certificate.NewRegistry())
}
