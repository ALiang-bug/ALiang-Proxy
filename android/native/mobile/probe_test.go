package mobile

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProbeResponseBounds(t *testing.T) {
	for _, test := range []struct {
		body   string
		status int
		good   bool
	}{
		{"Success", 200, true}, {strings.Repeat("Success", 1000), 200, false}, {"Success", 302, false}, {"not success", 200, false},
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(test.status); w.Write([]byte(test.body)) }))
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		result := measure(ctx, server.Client(), server.URL, false)
		cancel()
		server.Close()
		if result.OK != test.good {
			t.Fatal("incorrect response validation")
		}
	}
}
func TestProbeRejectsInvalidTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("Success")) }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := measure(ctx, &http.Client{Timeout: time.Second}, server.URL, false)
	if result.OK {
		t.Fatal("untrusted certificate accepted")
	}
}
func TestProbeDownloadBound(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(make([]byte, 5*1024*1024+1)) }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := measure(ctx, server.Client(), server.URL, true)
	if result.OK || result.Bytes != 5*1024*1024+1 {
		t.Fatal("oversized download reported as valid")
	}
}
func TestProtectFailure(t *testing.T) {
	p := &androidPlatform{protector: rejectProtector{}}
	if p.AutoDetectInterfaceControl(12) == nil {
		t.Fatal("failed socket protection accepted")
	}
}

type rejectProtector struct{}

func (rejectProtector) Protect(int32) bool { return false }

func TestProbeJobCancelBeforeRun(t *testing.T) {
	p, err := NewProbeJob(sample(), "test-node", "ali", false)
	if err != nil {
		t.Fatal(err)
	}
	p.Cancel()
	p.Cancel()
	result, err := p.Run()
	if err != nil || !strings.Contains(result, "cancelled") {
		t.Fatal("pre-cancel did not stop probe")
	}
	if _, err = p.Run(); err == nil {
		t.Fatal("reused single-use probe")
	}
}
func TestProbeCancellationStopsHTTPRequest(t *testing.T) {
	entered := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan probeResult, 1)
	go func() { done <- measure(ctx, server.Client(), server.URL, false) }()
	<-entered
	cancel()
	select {
	case result := <-done:
		if result.OK {
			t.Fatal("cancelled request passed")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation stalled")
	}
}

func TestZeroValueProbeJobIsSafe(t *testing.T) {
	var job ProbeJob
	job.Cancel()
	if _, err := job.Run(); err == nil {
		t.Fatal("uninitialized JNI probe accepted")
	}
}

func TestProbeJobCancelDuringNodeHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := listener.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	source := strings.ReplaceAll(sample(), "node.invalid", "127.0.0.1")
	source = strings.ReplaceAll(source, "port: 443", fmt.Sprintf("port: %d", listener.Addr().(*net.TCPAddr).Port))
	job, err := NewProbeJob(source, "test-node", "ali", false)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); job.Run() }()
	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(2 * time.Second):
		job.Cancel()
		t.Fatal("test node never reached")
	}
	job.Cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("native job cancellation did not interrupt TLS handshake")
	}
}
