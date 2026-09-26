package netguard

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
)

func TestBlocked(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":        true,
		"::1":              true,
		"10.1.2.3":         true,
		"172.16.0.1":       true,
		"192.168.1.1":      true,
		"fd00::1":          true, // ULA
		"169.254.169.254":  true, // cloud metadata
		"fe80::1":          true,
		"224.0.0.1":        true,
		"ff02::1":          true,
		"0.0.0.0":          true,
		"::":               true,
		"::ffff:127.0.0.1": true, // IPv4-mapped loopback
		"8.8.8.8":          false,
		"2001:4860::8888":  false,
		"100.64.0.1":       false, // CGNAT: left alone
		"198.18.0.1":       false, // fake-IP DNS range of Clash/Surge
	}
	for s, want := range cases {
		if got := blocked(netip.MustParseAddr(s)); got != want {
			t.Errorf("blocked(%s) = %v, want %v", s, got, want)
		}
	}
}

func TestControl(t *testing.T) {
	SetAllowPrivateForTesting(false)
	for _, addr := range []string{"127.0.0.1:443", "[::1]:43", "[fe80::1%eth0]:443", "169.254.169.254:80"} {
		if err := Control("tcp", addr, nil); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("Control(%s) = %v, want ErrBlockedAddress", addr, err)
		}
	}
	if err := Control("tcp", "8.8.8.8:443", nil); err != nil {
		t.Errorf("Control(public) = %v, want nil", err)
	}
	if err := Control("tcp", "not-an-address", nil); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("Control(garbage) = %v, want ErrBlockedAddress", err)
	}
	if err := Control("tcp", "example.com:443", nil); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("Control(unresolved host) = %v, want ErrBlockedAddress", err)
	}

	SetAllowPrivateForTesting(true)
	defer SetAllowPrivateForTesting(false)
	if err := Control("tcp", "127.0.0.1:443", nil); err != nil {
		t.Errorf("Control with the test allowance = %v, want nil", err)
	}
}

func TestCheckRedirect(t *testing.T) {
	SetAllowPrivateForTesting(false)
	req := func(raw string) *http.Request {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Request{URL: u}
	}
	httpsVia := []*http.Request{req("https://rdap.example/domain/x")}
	httpVia := []*http.Request{req("http://rdap.example/domain/x")}

	if err := CheckRedirect(req("https://rdap2.example/domain/x"), httpsVia); err != nil {
		t.Errorf("https→https = %v, want allowed", err)
	}
	if err := CheckRedirect(req("http://rdap2.example/domain/x"), httpVia); err != nil {
		t.Errorf("http→http = %v, want allowed (some registries only serve http)", err)
	}
	if err := CheckRedirect(req("http://rdap2.example/domain/x"), httpsVia); err == nil {
		t.Error("https→http downgrade must be refused")
	}
	if err := CheckRedirect(req("https://169.254.169.254/latest"), httpsVia); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("redirect to metadata IP = %v, want ErrBlockedAddress", err)
	}
	if err := CheckRedirect(req("https://[::1]/x"), httpsVia); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("redirect to loopback = %v, want ErrBlockedAddress", err)
	}

	long := make([]*http.Request, maxRedirects)
	for i := range long {
		long[i] = req("https://rdap.example/domain/x")
	}
	if err := CheckRedirect(req("https://rdap.example/domain/x"), long); err == nil {
		t.Errorf("redirect #%d must be refused", maxRedirects+1)
	}

	SetAllowPrivateForTesting(true)
	defer SetAllowPrivateForTesting(false)
	if err := CheckRedirect(req("https://127.0.0.1/x"), httpsVia); err != nil {
		t.Errorf("redirect to loopback with the test allowance = %v, want nil", err)
	}
}
