package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KincaidYang/whois/internal/serverlist"
)

// withMockWhoisServer starts a loopback WHOIS server answering every
// connection with the given response, and maps the given TLDs to it in
// serverlist.TLDToWhoisServer (restored on cleanup).
func withMockWhoisServer(t *testing.T, response string, tlds ...string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock WHOIS server: %v", err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1024)
				if _, err := c.Read(buf); err != nil {
					return
				}
				_, _ = c.Write([]byte(response))
			}(conn)
		}
	}()

	orig := serverlist.TLDToWhoisServer
	replaced := make(map[string]string, len(orig)+len(tlds))
	for k, v := range orig {
		replaced[k] = v
	}
	for _, tld := range tlds {
		replaced[tld] = listener.Addr().String()
	}
	serverlist.TLDToWhoisServer = replaced
	t.Cleanup(func() {
		serverlist.TLDToWhoisServer = orig
		_ = listener.Close()
	})
}

// TestWhoisDomainWithParser drives the WHOIS query path for a TLD that has a
// registered parser (.cn — WHOIS server, no RDAP), asserting the response is
// parsed into the regular JSON shape.
func TestWhoisDomainWithParser(t *testing.T) {
	withMockWhoisServer(t, `Domain Name: whoisparsertest.cn
ROID: 20030312s10001s00082127-cn
Domain Status: ok
Sponsoring Registrar: MockRegistrar
Name Server: ns1.example.cn
Name Server: ns2.example.cn
Registration Time: 2003-03-17 12:20:05
Expiration Time: 2027-03-17 12:20:05
DNSSEC: unsigned
`, "cn")

	w := httptest.NewRecorder()
	newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/domain/whoisparsertest.cn", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type: got %q", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"registrar":"MockRegistrar"`) {
		t.Errorf("parsed registrar missing: %s", body)
	}
	if !strings.Contains(body, "ns1.example.cn") {
		t.Errorf("parsed nameservers missing: %s", body)
	}
	if strings.Contains(body, `"unparsed":true`) {
		t.Errorf("response should be parsed, not raw-wrapped: %s", body)
	}

	// Second request must come from cache.
	w = httptest.NewRecorder()
	newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/domain/whoisparsertest.cn", nil))
	if got := w.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("X-Cache: got %q, want HIT", got)
	}
}

// TestWhoisDomainWithoutParser verifies a TLD with a WHOIS server but no
// parser gets the raw text wrapped in the stable JSON shape (unparsed=true).
func TestWhoisDomainWithoutParser(t *testing.T) {
	withMockWhoisServer(t, "Domain Name: test.zzwhoisonly\nSome unstructured registry text\n", "zzwhoisonly")

	w := httptest.NewRecorder()
	newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/domain/test.zzwhoisonly", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type: got %q", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"unparsed":true`) {
		t.Errorf("expected unparsed marker: %s", body)
	}
	if !strings.Contains(body, "Some unstructured registry text") {
		t.Errorf("raw text missing from rawText field: %s", body)
	}
}

// TestWhoisDomainRaw verifies ?raw=1 returns the bare WHOIS text as
// text/plain and serves the follow-up request from the raw: cache namespace.
func TestWhoisDomainRaw(t *testing.T) {
	const rawResponse = "Domain Name: rawtest.zzwhoisonly\nRaw registry answer\n"
	withMockWhoisServer(t, rawResponse, "zzwhoisonly")

	w := httptest.NewRecorder()
	newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/domain/rawtest.zzwhoisonly?raw=1", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type: got %q", ct)
	}
	if w.Body.String() != rawResponse {
		t.Errorf("raw body: %q", w.Body.String())
	}

	w = httptest.NewRecorder()
	newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/domain/rawtest.zzwhoisonly?raw=1", nil))
	if got := w.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("X-Cache: got %q, want HIT", got)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("cached raw Content-Type: got %q", ct)
	}
}

// TestWhoisDomainRawNoServer verifies ?raw=1 for a TLD without a WHOIS
// server is rejected with 404 (RDAP has no raw-text form to fall back to).
func TestWhoisDomainRawNoServer(t *testing.T) {
	w := httptest.NewRecorder()
	newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/domain/example.zzqqxxnotld?raw=1", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "No WHOIS server known") {
		t.Errorf("body: %s", w.Body.String())
	}
}

// TestWhoisDomainNotFound verifies a registry "no matching record" answer for
// a parser TLD maps to a 404 problem response.
func TestWhoisDomainNotFound(t *testing.T) {
	withMockWhoisServer(t, "No matching record.\n", "cn")

	w := httptest.NewRecorder()
	newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/domain/whoisnotfound.cn", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}
