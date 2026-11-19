package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

const lifecycleFixture = `
proxies:
  - name: offline-node
    type: trojan
    server: 127.0.0.1
    port: 9
    password: offline-fixture
    sni: offline.invalid
rules:
  - MATCH,offline-node
`

func TestCoreChild(t *testing.T) {
	if os.Getenv("ALIANG_TEST_CORE_CHILD") != "1" {
		return
	}
	os.Args = []string{os.Args[0], "run"}
	main()
	os.Exit(0)
}

func TestProxyStartupRejectsOccupiedPort(t *testing.T) {
	if os.Getenv("ALIANG_TEST_LOOPBACK") != "1" {
		t.Skip("set ALIANG_TEST_LOOPBACK=1 to exercise local sockets")
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	cfg, _, err := configuration(request{YAML: lifecycleFixture, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	core, err := newCore(context.Background(), cfg)
	if err == nil {
		_ = core.Close()
		t.Fatal("proxy started on an occupied port")
	}
	if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("existing listener no longer accepted connections: %v", err)
	}
	_ = accepted.Close()
}

func TestLoopbackProcessLifecycle(t *testing.T) {
	if os.Getenv("ALIANG_TEST_LOOPBACK") != "1" {
		t.Skip("set ALIANG_TEST_LOOPBACK=1 to exercise local sockets")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCoreChild$")
	command.Env = append(os.Environ(), "ALIANG_TEST_CORE_CHILD=1")
	command.Stderr = os.Stderr
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		if command.ProcessState == nil {
			cancel()
			_ = command.Wait()
		}
	})
	if err := json.NewEncoder(stdin).Encode(request{YAML: lifecycleFixture, Exit: "offline-node", Port: uint16(port)}); err != nil {
		t.Fatal(err)
	}
	var reply struct{ Ready bool }
	if err := json.NewDecoder(stdout).Decode(&reply); err != nil || !reply.Ready {
		t.Fatalf("core did not report readiness: %v", err)
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatalf("invalid SOCKS5 greeting: %v, %v", greeting, err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("core did not shut down on EOF: %v", err)
	}
	rebound, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatalf("listener was not released: %v", err)
	}
	_ = rebound.Close()
}
