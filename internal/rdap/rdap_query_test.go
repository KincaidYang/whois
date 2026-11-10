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
	"time"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/netguard"
	"github.com/KincaidYang/whois/internal/utils"
)

// TestMain seeds proxy settings before any test runs: initProxy is guarded by
// a package-level sync.Once, so the configuration must be in place before the
// first getHTTPClient call anywhere in this test binary. Upstream stand-ins
// run on loopback, which netguard refuses outside tests.
func TestMain(m *testing.M) {
	netguard.SetAllowPrivateForTesting(true)
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

// TestGetHTTPClientNoTLD covers IP and ASN queries, which have no TLD: only
// the catch-all "all" entry proxies them, never a TLD entry.
func TestGetHTTPClientNoTLD(t *testing.T) {
	if got := getHTTPClient(""); got != config.HttpClient {
		t.Fatalf("without \"all\", a query with no TLD should get config.HttpClient, got %+v", got)
	}
	// An empty entry in proxy.suffixes must not match the empty TLD.
	proxySuffixSet[""] = struct{}{}
	if got := getHTTPClient(""); got != config.HttpClient {
		t.Fatalf("an empty suffix entry must not proxy IP/ASN queries, got %+v", got)
	}
	delete(proxySuffixSet, "")

	proxySuffixSet["all"] = struct{}{}
	defer delete(proxySuffixSet, "all")
	if got := getHTTPClient(""); got != proxyClient {
		t.Fatalf("with \"all\", a query with no TLD should get the proxy client, got %+v", got)
	}
}

func TestDoRDAPRequestSendsUserAgent(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("User-Agent"))
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	if _, err := doRDAPRequest(context.Background(), config.HttpClient, srv.URL); err != nil {
		t.Fatalf("doRDAPRequest: %v", err)
	}
	if ua, _ := got.Load().(string); ua != config.UserAgent() || !strings.HasPrefix(ua, "whois/") {
		t.Fatalf("User-Agent = %q, want %q", ua, config.UserAgent())
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

// TestUpstreamClientRefusesLoopback checks the production client end to end:
// with the test allowance off, config.HttpClient must refuse to connect to a
// loopback upstream (here an httptest server). The redirect policy is covered
// by netguard's own tests.
func TestUpstreamClientRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	netguard.SetAllowPrivateForTesting(false)
	defer netguard.SetAllowPrivateForTesting(true)
	if _, err := doRDAPRequest(context.Background(), config.HttpClient, srv.URL+"/domain/example.com"); !errors.Is(err, netguard.ErrBlockedAddress) {
		t.Errorf("request to a loopback upstream: err = %v, want ErrBlockedAddress", err)
	}
}

func TestDoRDAPRequestRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	_, err := doRDAPRequest(context.Background(), config.HttpClient, srv.URL)
	var limited *utils.UpstreamRateLimitedError
	if !errors.As(err, &limited) || !errors.Is(err, utils.ErrUpstreamRateLimited) {
		t.Fatalf("expected UpstreamRateLimitedError, got %v", err)
	}
	if limited.RetryAfter != 2*time.Minute {
		t.Errorf("RetryAfter = %s, want 2m", limited.RetryAfter)
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		value string
		want  time.Duration
	}{
		{"", 0},
		{"30", 30 * time.Second},
		{" 30 ", 30 * time.Second},
		{"0", 0},
		{"-5", 0},
		{"soon", 0},
		{"1.5", 0},
		{"7200", maxRetryAfter},
		{"99999999999999999999", 0}, // overflows int64: malformed
		{"9223372036854775807", maxRetryAfter},
		{"Tue, 10 Nov 2026 12:01:00 GMT", time.Minute},
		{"Tue, 10 Nov 2026 11:00:00 GMT", 0},             // in the past
		{"Wed, 11 Nov 2026 12:00:00 GMT", maxRetryAfter}, // a day away
	}
	for _, tt := range tests {
		if got := retryAfter(tt.value, now); got != tt.want {
			t.Errorf("retryAfter(%q) = %s, want %s", tt.value, got, tt.want)
		}
	}
}
