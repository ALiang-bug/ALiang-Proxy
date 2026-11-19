package mobile

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	sj "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// Tests the Android compiler's actual outbound options over loopback. No public
// host, subscription, private credential or device network setting is used.
func TestCompiledProtocolsLoopback(t *testing.T) {
	for _, kind := range []string{"vless", "trojan"} {
		t.Run(kind, func(t *testing.T) { protocolRoundtrip(t, kind) })
	}
}
func protocolRoundtrip(t *testing.T, kind string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	priv, _ := x509.MarshalECPrivateKey(key)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: priv})
	var connections sync.Map
	defer func() { connections.Range(func(k, v any) bool { k.(net.Conn).Close(); return true }) }()
	handshake, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	defer tcp.Close()
	port := tcp.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			connections.Store(c, true)
			go func() { defer c.Close(); defer connections.Delete(c); io.Copy(c, c) }()
		}
	}()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	serverPort := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	reality, _ := ecdh.X25519().GenerateKey(rand.Reader)
	const uuid = "00000000-0000-4000-8000-000000000001"
	serverTLS := map[string]any{"enabled": true, "server_name": "localhost", "certificate": []string{string(cert)}, "key": []string{string(privPEM)}}
	users := []any{map[string]any{"password": "synthetic-password"}}
	authYAML := "    password: synthetic-password\n"
	if kind == "vless" {
		users = []any{map[string]any{"uuid": uuid, "flow": "xtls-rprx-vision"}}
		serverTLS = map[string]any{"enabled": true, "server_name": "localhost", "reality": map[string]any{"enabled": true, "private_key": base64.RawURLEncoding.EncodeToString(reality.Bytes()), "short_id": []string{"0123456789abcdef"}, "handshake": map[string]any{"server": "127.0.0.1", "server_port": handshake.Addr().(*net.TCPAddr).Port}}}
		authYAML = fmt.Sprintf("    uuid: %s\n    flow: xtls-rprx-vision\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: %s\n      short-id: '0123456789abcdef'\n", uuid, base64.RawURLEncoding.EncodeToString(reality.PublicKey().Bytes()))
	}
	ctx := coreContext()
	optionsJSON, _ := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": kind, "listen": "127.0.0.1", "listen_port": serverPort, "users": users, "tls": serverTLS}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "echo"}}, "route": map[string]any{"final": "echo"}})
	// Only the test context exposes a server or direct outbound.
	inRegistry := service.FromContext[option.InboundOptionsRegistry](ctx)
	_ = inRegistry
	// coreContext uses concrete registries accessible through adapter services.
	inboundRegistry := service.FromContext[adapter.InboundRegistry](ctx)
	outboundRegistry := service.FromContext[adapter.OutboundRegistry](ctx)
	vless.RegisterInbound(inboundRegistry.(*inbound.Registry))
	trojan.RegisterInbound(inboundRegistry.(*inbound.Registry))
	direct.RegisterOutbound(outboundRegistry.(*outbound.Registry))
	opts, err := sj.UnmarshalExtendedContext[option.Options](ctx, optionsJSON)
	if err != nil {
		t.Fatal(err)
	}
	server, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf("proxies:\n  - name: proxy\n    type: %s\n    server: 127.0.0.1\n    port: %d\n    tls: true\n    udp: true\n    servername: localhost\n%s", kind, serverPort, authYAML)
	data, _, err := compiled(source, "proxy", "{}", "ali")
	if err != nil {
		t.Fatal(err)
	}
	clientCtx, cancel := context.WithCancel(coreContext())
	defer cancel()
	protected := &countingProtector{}
	clientCtx = service.ContextWith[adapter.PlatformInterface](clientCtx, &androidPlatform{fd: -1, protector: protected})
	clientOptions, err := sj.UnmarshalExtendedContext[option.Options](clientCtx, data)
	if err != nil {
		t.Fatal(err)
	}
	clientOptions.Inbounds = nil
	clientOptions.Route.Rules = nil
	if kind == "trojan" {
		clientOptions.Outbounds[0].Options.(*option.TrojanOutboundOptions).TLS.Certificate = []string{string(cert)}
	}
	client, err := box.New(box.Options{Context: clientCtx, Options: clientOptions})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err = client.Start(); err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"tcp", "udp"} {
		c, err := client.Outbound().Default().DialContext(clientCtx, network, M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", port)))
		if err != nil {
			t.Fatal(network, err)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		payload := []byte("android-core-loopback")
		if _, err = c.Write(payload); err != nil {
			c.Close()
			t.Fatal(network, err)
		}
		reply := make([]byte, len(payload))
		_, err = io.ReadFull(c, reply)
		c.Close()
		if err != nil || !bytes.Equal(reply, payload) {
			t.Fatal(network, "roundtrip_failed", err)
		}
	}
	if protected.calls.Load() < 2 {
		t.Fatal("outbound sockets bypassed the platform protection callback")
	}
}

type countingProtector struct{ calls atomic.Int64 }

func (p *countingProtector) Protect(int32) bool { p.calls.Add(1); return true }
