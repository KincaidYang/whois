package rdap

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/metrics"
	"github.com/KincaidYang/whois/internal/serverlist"
	"github.com/KincaidYang/whois/internal/utils"
)

// maxResponseSize caps how much we read from an RDAP server to guard against
// a misbehaving or malicious server exhausting memory.
const maxResponseSize = 2 << 20 // 2 MiB

// proxyClient is a pre-built HTTP client for proxied RDAP requests.
// Built once on first use (after config.Load has run) to enable connection
// pool reuse across requests.
var proxyClient *http.Client

// proxySuffixSet is a set built from config.ProxySuffixes for O(1) lookup.
var proxySuffixSet map[string]struct{}

// proxyOnce defers proxy setup until the first query, because the config
// package no longer initializes itself in init(); proxy settings only exist
// once config.Load has been called.
var proxyOnce sync.Once

func initProxy() {
	if config.ProxyServer != "" {
		proxyURL, err := url.Parse(config.ProxyServer)
		if err == nil {
			if config.ProxyUsername != "" && config.ProxyPassword != "" {
				proxyURL.User = url.UserPassword(config.ProxyUsername, config.ProxyPassword)
			}
			proxyClient = &http.Client{
				Timeout: config.HttpClient.Timeout,
				Transport: &http.Transport{
					Proxy:               http.ProxyURL(proxyURL),
					MaxIdleConns:        100,
					MaxIdleConnsPerHost: 10,
					IdleConnTimeout:     90 * time.Second,
				},
			}
		}
	}

	proxySuffixSet = make(map[string]struct{}, len(config.ProxySuffixes))
	for _, s := range config.ProxySuffixes {
		proxySuffixSet[s] = struct{}{}
	}
}

// getHTTPClient returns an HTTP client with appropriate proxy settings.
// Returns the pre-built proxyClient for proxied TLDs, or config.HttpClient otherwise.
func getHTTPClient(tld string) *http.Client {
	proxyOnce.Do(initProxy)
	if proxyClient != nil {
		_, matchTLD := proxySuffixSet[tld]
		_, matchAll := proxySuffixSet["all"]
		if matchTLD || matchAll {
			return proxyClient
		}
	}
	return config.HttpClient
}

// doRDAPRequest performs the common RDAP HTTP request logic
func doRDAPRequest(ctx context.Context, client *http.Client, url string) (result string, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// Read one byte past the limit so an oversized response is detected and
		// rejected rather than silently truncated.
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
		if err != nil {
			return "", err
		}
		if len(body) > maxResponseSize {
			return "", fmt.Errorf("RDAP response from %s exceeds %d bytes", url, maxResponseSize)
		}
		return string(body), nil
	case http.StatusNotFound:
		return "", utils.ErrResourceNotFound
	case http.StatusForbidden:
		return "", utils.ErrQueryDenied
	default:
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

// RDAPQuery function is used to query the RDAP information for a given domain.
func RDAPQuery(ctx context.Context, domain, tld string) (string, error) {
	rdapServer, ok := serverlist.LookupRdapServer(tld)
	if !ok {
		return "", fmt.Errorf("no RDAP server known for TLD: %s", tld)
	}

	slog.DebugContext(ctx, "querying RDAP", "type", "domain", "query", domain, "tld", tld, "server", rdapServer)

	start := time.Now()
	defer func() {
		metrics.UpstreamDuration.WithLabelValues("rdap", tld).Observe(time.Since(start).Seconds())
	}()
	client := getHTTPClient(tld)
	// PathEscape is defence in depth: entry-point validation already rejects
	// URL metacharacters, but the query value must never rewrite the URL path.
	return doRDAPRequest(ctx, client, rdapServer+"domain/"+url.PathEscape(domain))
}

// RDAPQueryIP queries the RDAP information for a given IP address.
// serverURL is obtained by the caller via serverlist.LookupIPKey.
func RDAPQueryIP(ctx context.Context, ip, serverURL string) (string, error) {
	if serverURL == "" {
		return "", fmt.Errorf("no RDAP server known for IP: %s", ip)
	}
	slog.DebugContext(ctx, "querying RDAP", "type", "ip", "query", ip, "server", serverURL)
	start := time.Now()
	defer func() {
		metrics.UpstreamDuration.WithLabelValues("rdap", "_ip").Observe(time.Since(start).Seconds())
	}()
	// CIDR input ("192.0.2.0/24") maps to the RFC 9082 ip/<prefix>/<length>
	// form, so the slash must survive as a path separator: escape each
	// segment individually.
	segments := strings.Split(ip, "/")
	for i := range segments {
		segments[i] = url.PathEscape(segments[i])
	}
	return doRDAPRequest(ctx, config.HttpClient, serverURL+"ip/"+strings.Join(segments, "/"))
}

// RDAPQueryASN queries the RDAP information for a given ASN.
// serverURL is obtained by the caller via serverlist.LookupASNKey.
func RDAPQueryASN(ctx context.Context, as, serverURL string) (string, error) {
	if serverURL == "" {
		return "", fmt.Errorf("no RDAP server known for ASN: %s", as)
	}
	slog.DebugContext(ctx, "querying RDAP", "type", "asn", "query", as, "server", serverURL)
	start := time.Now()
	defer func() {
		metrics.UpstreamDuration.WithLabelValues("rdap", "_asn").Observe(time.Since(start).Seconds())
	}()
	return doRDAPRequest(ctx, config.HttpClient, serverURL+"autnum/"+url.PathEscape(as))
}
