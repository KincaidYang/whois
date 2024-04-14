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

// contains function is used to check if a string is in a slice of strings.
func contains(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}

// RDAPQuery function is used to query the RDAP (Registration Data Access Protocol) information for a given domain.
func RDAPQuery(domain, tld string) (string, error) {
	rdapServer, ok := server_lists.TLDToRdapServer[tld]
	if !ok {
		return "", fmt.Errorf("no RDAP server known for TLD: %s", tld)
	}

	// Log the request for the RDAP query
	log.Printf("Querying RDAP for domain: %s with TLD: %s on server: %s\n", domain, tld, rdapServer)

	req, err := http.NewRequest("GET", rdapServer+"domain/"+domain, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/rdap+json")

	if contains(config.ProxySuffixes, tld) || contains(config.ProxySuffixes, "all") {
		proxyURL, _ := url.Parse(config.ProxyServer)
		config.HttpClient.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
	} else {
		config.HttpClient.Transport = &http.Transport{}
	}

	resp, err := config.HttpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", errors.New("resource not found")
	} else if resp.StatusCode == http.StatusForbidden {
		return "", errors.New("the registry denied the query")
	} else if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// RDAPQueryIP function is used to query the RDAP information for a given IP address.
func RDAPQueryIP(ip, tld string) (string, error) {
	rdapServer, ok := server_lists.TLDToRdapServer[tld]
	if !ok {
		return "", fmt.Errorf("no RDAP server known for IP: %s", ip)
	}

	// Log the request for the RDAP query
	log.Printf("Querying RDAP for IP: %s with TLD: %s on server: %s\n", ip, tld, rdapServer)

	req, err := http.NewRequest("GET", rdapServer+"ip/"+ip, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/rdap+json")

	if contains(config.ProxySuffixes, tld) || contains(config.ProxySuffixes, "all") {
		proxyURL, _ := url.Parse(config.ProxyServer)
		config.HttpClient.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
	} else {
		config.HttpClient.Transport = &http.Transport{}
	}

	resp, err := config.HttpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", errors.New("resource not found")
	} else if resp.StatusCode == http.StatusForbidden {
		return "", errors.New("the registry denied the query")
	} else if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// rdapQueryASN function is used to query the RDAP information for a given ASN.
func RDAPQueryASN(as, tld string) (string, error) {
	rdapServer, ok := server_lists.TLDToRdapServer[tld]
	if !ok {
		return "", fmt.Errorf("no RDAP server known for ASN: %s", as)
	}

	// Log the request for the RDAP query
	log.Printf("Querying RDAP for AS: %s with TLD: %s on server: %s\n", as, tld, rdapServer)

	req, err := http.NewRequest("GET", rdapServer+"autnum/"+as, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/rdap+json")

	if contains(config.ProxySuffixes, tld) || contains(config.ProxySuffixes, "all") {
		proxyURL, _ := url.Parse(config.ProxyServer)
		config.HttpClient.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
	} else {
		config.HttpClient.Transport = &http.Transport{}
	}

	resp, err := config.HttpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", errors.New("resource not found")
	} else if resp.StatusCode == http.StatusForbidden {
		return "", errors.New("the registry denied the query")
	} else if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}
