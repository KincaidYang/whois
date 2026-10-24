package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KincaidYang/whois/internal/config"
)

// withMetricsAddr sets server.metricsAddr for the duration of a test.
func withMetricsAddr(t *testing.T, addr string) {
	t.Helper()
	old := config.MetricsAddr
	config.MetricsAddr = addr
	t.Cleanup(func() { config.MetricsAddr = old })
}

func getMetrics(key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/metrics", nil)
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	return authRequest(req)
}

// TestMetricsOnMainPortByDefault verifies /metrics stays on the main port
// when server.metricsAddr is unset.
func TestMetricsOnMainPortByDefault(t *testing.T) {
	withMetricsAddr(t, "")
	w := getMetrics("")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "go_goroutines") {
		t.Fatalf("expected metrics on the main port, got %d", w.Code)
	}
}

// TestMetricsAddrRemovesMainPortRoute verifies that with server.metricsAddr
// set, the main port no longer serves /metrics, even to a valid key.
func TestMetricsAddrRemovesMainPortRoute(t *testing.T) {
	withMetricsAddr(t, "127.0.0.1:9100")
	withTestAuthKeys(t, "metrics-key")
	w := getMetrics("metrics-key")
	if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "go_goroutines") {
		t.Fatalf("main port still serves /metrics: %d", w.Code)
	}
}

// TestStartMetricsServer verifies the separate listener serves /metrics
// without a key while auth is on, and nothing else.
func TestStartMetricsServer(t *testing.T) {
	withMetricsAddr(t, "127.0.0.1:0")
	withTestAuthKeys(t, "metrics-key")

	srv, err := startMetricsServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	resp, err := http.Get("http://" + srv.Addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "go_goroutines") {
		t.Fatalf("metrics listener: expected metrics without a key, got %d", resp.StatusCode)
	}

	resp, err = http.Get("http://" + srv.Addr + "/info")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("metrics listener served /info: %d", resp.StatusCode)
	}
}

func TestStartMetricsServerUnset(t *testing.T) {
	withMetricsAddr(t, "")
	srv, err := startMetricsServer()
	if srv != nil || err != nil {
		t.Fatalf("unset metricsAddr: got %v, %v", srv, err)
	}
}

// TestStartMetricsServerBindError verifies a busy address is reported, so
// startup can stop instead of running without its metrics listener.
func TestStartMetricsServerBindError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	withMetricsAddr(t, ln.Addr().String())

	if srv, err := startMetricsServer(); err == nil {
		_ = srv.Shutdown(context.Background())
		t.Fatal("expected a bind error for an address in use")
	}
}

// TestServeMetricsLogsListenerFailure covers the listener failing under a
// running metrics server: serveMetrics returns instead of hanging.
func TestServeMetricsLogsListenerFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	done := make(chan struct{})
	go func() {
		serveMetrics(&http.Server{}, ln)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveMetrics did not return after its listener failed")
	}
}

// TestMustStartMetricsServerExitsOnError verifies a busy address exits the
// process with status 1.
func TestMustStartMetricsServerExitsOnError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	withMetricsAddr(t, ln.Addr().String())

	code := -1
	oldExit := exit
	exit = func(c int) { code = c }
	t.Cleanup(func() { exit = oldExit })

	if srv := mustStartMetricsServer(); srv != nil {
		_ = srv.Shutdown(context.Background())
	}
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMustStartMetricsServer(t *testing.T) {
	withMetricsAddr(t, "127.0.0.1:0")
	srv := mustStartMetricsServer()
	if srv == nil {
		t.Fatal("expected a running metrics server")
	}
	shutdownMetricsServer(context.Background(), srv)
	if _, err := http.Get("http://" + srv.Addr + "/metrics"); err == nil {
		t.Error("metrics server still accepting connections after shutdown")
	}
	shutdownMetricsServer(context.Background(), nil) // unset: no-op
}

// TestShutdownMetricsServerTimeout covers a scrape that outlives the
// shutdown deadline: the error is logged and shutdown still returns.
func TestShutdownMetricsServerTimeout(t *testing.T) {
	withMetricsAddr(t, "127.0.0.1:0")
	srv, err := startMetricsServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	// A connection with half a request stays active, so Shutdown cannot
	// finish before its (already expired) deadline.
	conn, err := net.Dial("tcp", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write([]byte("GET /metrics HTTP/1.1\r\nHost: x\r\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // let the server pick the connection up

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	shutdownMetricsServer(ctx, srv)
}
