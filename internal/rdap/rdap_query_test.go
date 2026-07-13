package rdap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/utils"
)

// TestMain seeds proxy settings before any test runs: initProxy is guarded by
// a package-level sync.Once, so the configuration must be in place before the
// first getHTTPClient call anywhere in this test binary.
func TestMain(m *testing.M) {
	config.ProxyServer = "http://proxy.invalid:3128"
	config.ProxyUsername = "user"
	config.ProxyPassword = "pass"
	config.ProxySuffixes = []string{"proxied"}
	os.Exit(m.Run())
}

func TestGetHTTPClientProxySelection(t *testing.T) {
	proxied := getHTTPClient("proxied")
	if proxied == config.HttpClient {
		t.Fatal("TLD in proxy.suffixes should get the proxy client, got the default client")
	}
	if proxied != proxyClient {
		t.Fatalf("expected the shared proxy client, got %+v", proxied)
	}
	if direct := getHTTPClient("com"); direct != config.HttpClient {
		t.Fatalf("TLD outside proxy.suffixes should get config.HttpClient, got %+v", direct)
	}
}

func TestDoRDAPRequestStatusMapping(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantErr error
	}{
		{"not found", http.StatusNotFound, utils.ErrResourceNotFound},
		{"forbidden", http.StatusForbidden, utils.ErrQueryDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()

			_, err := doRDAPRequest(context.Background(), config.HttpClient, srv.URL)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("status %d: expected %v, got %v", tt.status, tt.wantErr, err)
			}
		})
	}
}

func TestDoRDAPRequestUnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	_, err := doRDAPRequest(context.Background(), config.HttpClient, srv.URL)
	if err == nil || !strings.Contains(err.Error(), "unexpected status code: 502") {
		t.Fatalf("expected unexpected-status error, got %v", err)
	}
}

func TestDoRDAPRequestOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 64<<10)
		for written := 0; written <= maxResponseSize; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	_, err := doRDAPRequest(context.Background(), config.HttpClient, srv.URL)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversized-response error, got %v", err)
	}
}

func TestDoRDAPRequestInvalidURL(t *testing.T) {
	if _, err := doRDAPRequest(context.Background(), config.HttpClient, "://bad"); err == nil {
		t.Fatal("expected error for unparseable URL")
	}
}

func TestRDAPQueryIPNoServer(t *testing.T) {
	if _, err := RDAPQueryIP(context.Background(), "192.0.2.1", ""); err == nil {
		t.Fatal("expected error when no RDAP server is known for the IP")
	}
}

func TestRDAPQueryASNNoServer(t *testing.T) {
	if _, err := RDAPQueryASN(context.Background(), "64500", ""); err == nil {
		t.Fatal("expected error when no RDAP server is known for the ASN")
	}
}

func TestRDAPQueryIP(t *testing.T) {
	const body = `{"objectClassName": "ip network", "handle": "NET-192-0-2-0-1"}`
	// Written by the httptest handler goroutine, read by the test goroutine.
	var gotPath atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	got, err := RDAPQueryIP(context.Background(), "192.0.2.1", srv.URL+"/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != body {
		t.Errorf("response body: %q", got)
	}
	if got, _ := gotPath.Load().(string); got != "/ip/192.0.2.1" {
		t.Errorf("request path: %q", got)
	}
}

// TestRDAPQueryIPCIDR verifies the slash in a CIDR query survives as a path
// separator (RFC 9082 ip/<prefix>/<length> form).
func TestRDAPQueryIPCIDR(t *testing.T) {
	var gotPath atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	if _, err := RDAPQueryIP(context.Background(), "192.0.2.0/24", srv.URL+"/"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, _ := gotPath.Load().(string); got != "/ip/192.0.2.0/24" {
		t.Errorf("request path: %q", got)
	}
}

func TestRDAPQueryASN(t *testing.T) {
	const body = `{"objectClassName": "autnum", "handle": "AS64500"}`
	var gotPath atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	got, err := RDAPQueryASN(context.Background(), "64500", srv.URL+"/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != body {
		t.Errorf("response body: %q", got)
	}
	if got, _ := gotPath.Load().(string); got != "/autnum/64500" {
		t.Errorf("request path: %q", got)
	}
}
