package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func TestTrojanSOCKSForwarding(t *testing.T) {
	if os.Getenv("ALIANG_TEST_LOOPBACK") != "1" {
		t.Skip("set ALIANG_TEST_LOOPBACK=1 to exercise local sockets")
	}
	fixture := httptest.NewTLSServer(nil)
	cert := fixture.TLS.Certificates[0]
	fixture.Close()
	server, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	received := make(chan error, 1)
	go func() {
		conn, err := server.Accept()
		if err != nil {
			received <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		// Trojan password hash, CRLF, CONNECT command, IPv4 address, port, CRLF.
		var header [68]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			received <- err
			return
		}
		wantTarget := []byte{1, 1, 192, 0, 2, 10, 0, 80, 13, 10}
		if !bytes.Equal(header[58:], wantTarget) {
			received <- fmt.Errorf("unexpected Trojan request header")
			return
		}
		body := make([]byte, len("offline round trip"))
		if _, err := io.ReadFull(conn, body); err != nil {
			received <- err
			return
		}
		_, err = conn.Write(body)
		received <- err
	}()

	temporary, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := temporary.Addr().(*net.TCPAddr).Port
	_ = temporary.Close()
	yaml := fmt.Sprintf("proxies:\n  - name: test\n    type: trojan\n    server: 127.0.0.1\n    port: %d\n    password: offline-fixture\n",
		server.Addr().(*net.TCPAddr).Port)
	data, _, err := configuration(request{YAML: yaml, Port: uint16(port)})
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	// Trust the local fixture certificate exclusively in this test.
	tlsOptions := config["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)
	tlsOptions["certificate"] = []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))}
	data, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	core, err := newCore(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", "192.0.2.10:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	want := []byte("offline round trip")
	if _, err := conn.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("proxy round trip failed: %q, %v", got, err)
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
}
