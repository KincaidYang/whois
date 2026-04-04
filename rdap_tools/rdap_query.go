package rdap_tools

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/KincaidYang/whois/config"
	"github.com/KincaidYang/whois/server_lists"
)

// Common errors for RDAP queries
var (
	ErrResourceNotFound = errors.New("resource not found")
	ErrQueryDenied      = errors.New("the registry denied the query")
)

// proxyClient is a pre-built HTTP client for proxied RDAP requests.
// Initialized once at startup to enable connection pool reuse across requests.
var proxyClient *http.Client

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
}

// contains function is used to check if a string is in a slice of strings.
func contains(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}

// getHTTPClient returns an HTTP client with appropriate proxy settings.
// Returns the pre-built proxyClient for proxied TLDs, or config.HttpClient otherwise.
func getHTTPClient(tld string) *http.Client {
	if proxyClient != nil && (contains(config.ProxySuffixes, tld) || contains(config.ProxySuffixes, "all")) {
		return proxyClient
	}
	return config.HttpClient
}

// doRDAPRequest performs the common RDAP HTTP request logic
func doRDAPRequest(client *http.Client, url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
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
		var buf bytes.Buffer
		_, err = io.Copy(&buf, resp.Body)
		if err != nil {
			return "", err
		}
		return buf.String(), nil
	case http.StatusNotFound:
		return "", ErrResourceNotFound
	case http.StatusForbidden:
		return "", ErrQueryDenied
	default:
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

// RDAPQuery function is used to query the RDAP information for a given domain.
func RDAPQuery(domain, tld string) (string, error) {
	rdapServer, ok := server_lists.TLDToRdapServer[tld]
	if !ok {
		return "", fmt.Errorf("no RDAP server known for TLD: %s", tld)
	}

	log.Printf("Querying RDAP for domain: %s with TLD: %s on server: %s\n", domain, tld, rdapServer)

	client := getHTTPClient(tld)
	return doRDAPRequest(client, rdapServer+"domain/"+domain)
}

// RDAPQueryIP function is used to query the RDAP information for a given IP address.
func RDAPQueryIP(ip, tld string) (string, error) {
	rdapServer, ok := server_lists.TLDToRdapServer[tld]
	if !ok {
		return "", fmt.Errorf("no RDAP server known for IP: %s", ip)
	}

	log.Printf("Querying RDAP for IP: %s with TLD: %s on server: %s\n", ip, tld, rdapServer)

	client := getHTTPClient(tld)
	return doRDAPRequest(client, rdapServer+"ip/"+ip)
}

// RDAPQueryASN function is used to query the RDAP information for a given ASN.
func RDAPQueryASN(as, tld string) (string, error) {
	rdapServer, ok := server_lists.TLDToRdapServer[tld]
	if !ok {
		return "", fmt.Errorf("no RDAP server known for ASN: %s", as)
	}

	log.Printf("Querying RDAP for AS: %s with TLD: %s on server: %s\n", as, tld, rdapServer)

	client := getHTTPClient(tld)
	return doRDAPRequest(client, rdapServer+"autnum/"+as)
}
