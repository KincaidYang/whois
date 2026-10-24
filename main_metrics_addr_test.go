package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
