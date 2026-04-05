package rdap_tools

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/KincaidYang/whois/config"
	"github.com/KincaidYang/whois/metrics"
	"github.com/KincaidYang/whois/server_lists"
	"github.com/KincaidYang/whois/utils"
)

// proxyClient is a pre-built HTTP client for proxied RDAP requests.
// Initialized once at startup to enable connection pool reuse across requests.
var proxyClient *http.Client

// proxySuffixSet is a set built from config.ProxySuffixes for O(1) lookup.
var proxySuffixSet map[string]struct{}

func init() {
	if config.ProxyServer != "" {
		proxyURL, err := url.Parse(config.ProxyServer)
		if err == nil {
			if config.ProxyUsername != "" && config.ProxyPassword != "" {
				proxyURL.User = url.UserPassword(config.ProxyUsername, config.ProxyPassword)
			}
			proxyClient = &http.Client{
				Timeout: config.HttpClient.Timeout,
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
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
	start := time.Now()
	defer func() {
		metrics.UpstreamDuration.WithLabelValues("rdap").Observe(time.Since(start).Seconds())
	}()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
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
	rdapServer, ok := server_lists.TLDToRdapServer[tld]
	if !ok {
		return "", fmt.Errorf("no RDAP server known for TLD: %s", tld)
	}

	slog.Debug("querying RDAP", "type", "domain", "query", domain, "tld", tld, "server", rdapServer)

	client := getHTTPClient(tld)
	return doRDAPRequest(ctx, client, rdapServer+"domain/"+domain)
}

// RDAPQueryIP function is used to query the RDAP information for a given IP address.
func RDAPQueryIP(ctx context.Context, ip, tld string) (string, error) {
	rdapServer, ok := server_lists.TLDToRdapServer[tld]
	if !ok {
		return "", fmt.Errorf("no RDAP server known for IP: %s", ip)
	}

	slog.Debug("querying RDAP", "type", "ip", "query", ip, "tld", tld, "server", rdapServer)

	client := getHTTPClient(tld)
	return doRDAPRequest(ctx, client, rdapServer+"ip/"+ip)
}

// RDAPQueryASN function is used to query the RDAP information for a given ASN.
func RDAPQueryASN(ctx context.Context, as, tld string) (string, error) {
	rdapServer, ok := server_lists.TLDToRdapServer[tld]
	if !ok {
		return "", fmt.Errorf("no RDAP server known for ASN: %s", as)
	}

	slog.Debug("querying RDAP", "type", "asn", "query", as, "tld", tld, "server", rdapServer)

	client := getHTTPClient(tld)
	return doRDAPRequest(ctx, client, rdapServer+"autnum/"+as)
}
