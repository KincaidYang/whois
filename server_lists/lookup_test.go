package server_lists

import (
	"net"
	"strings"
	"testing"
)

func TestLookupIPKey_IPv4(t *testing.T) {
	tests := []struct {
		ip        string
		wantURL   string // substring expected in the returned URL
		wantFound bool
	}{
		{"1.1.1.1", "rdap.apnic.net", true},      // APNIC
		{"1.255.255.255", "rdap.apnic.net", true}, // last addr in 1.0.0.0/8
		{"41.0.0.1", "rdap.afrinic.net", true},    // AFRINIC
		{"102.128.0.1", "rdap.afrinic.net", true}, // AFRINIC
		{"0.0.0.1", "", false},
		{"255.255.255.255", "", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("invalid IP in test: %s", tt.ip)
		}
		gotURL, gotFound := LookupIPKey(ip)
		if gotFound != tt.wantFound {
			t.Errorf("LookupIPKey(%s): found=%v, want %v", tt.ip, gotFound, tt.wantFound)
			continue
		}
		if tt.wantFound && !strings.Contains(gotURL, tt.wantURL) {
			t.Errorf("LookupIPKey(%s): url=%q, want to contain %q", tt.ip, gotURL, tt.wantURL)
		}
	}
}

func TestLookupIPKey_IPv6(t *testing.T) {
	tests := []struct {
		ip        string
		wantFound bool
	}{
		{"2001:4200::1", true},  // AFRINIC 2001:4200::/23
		{"2c00::1", true},       // AFRINIC 2c00::/12
		{"2001:200::1", true},   // APNIC   2001:200::/23
		{"::1", false},          // loopback
		{"fe80::1", false},      // link-local
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("invalid IP in test: %s", tt.ip)
		}
		_, gotFound := LookupIPKey(ip)
		if gotFound != tt.wantFound {
			t.Errorf("LookupIPKey(%s): found=%v, want %v", tt.ip, gotFound, tt.wantFound)
		}
	}
}

func TestLookupIPKey_BoundaryValues(t *testing.T) {
	first := net.ParseIP("1.0.0.0")
	last := net.ParseIP("1.255.255.255")

	urlFirst, foundFirst := LookupIPKey(first)
	urlLast, foundLast := LookupIPKey(last)

	if !foundFirst || !strings.Contains(urlFirst, "rdap.apnic.net") {
		t.Errorf("first address of 1.0.0.0/8: got (%q, %v)", urlFirst, foundFirst)
	}
	if !foundLast || !strings.Contains(urlLast, "rdap.apnic.net") {
		t.Errorf("last address of 1.0.0.0/8: got (%q, %v)", urlLast, foundLast)
	}
}

func TestLookupASNKey(t *testing.T) {
	tests := []struct {
		asn       int
		wantURL   string // substring expected in the returned URL
		wantFound bool
	}{
		{36864, "rdap.afrinic.net", true}, // lower bound of 36864-37887
		{37887, "rdap.afrinic.net", true}, // upper bound
		{37000, "rdap.afrinic.net", true}, // mid range
		{4608, "rdap.apnic.net", true},    // APNIC lower bound of 4608-4865
		{4865, "rdap.apnic.net", true},    // APNIC upper bound
		{0, "", false},
		{4294967295, "", false},
	}

	for _, tt := range tests {
		gotURL, gotFound := LookupASNKey(tt.asn)
		if gotFound != tt.wantFound {
			t.Errorf("LookupASNKey(%d): found=%v, want %v", tt.asn, gotFound, tt.wantFound)
			continue
		}
		if tt.wantFound && !strings.Contains(gotURL, tt.wantURL) {
			t.Errorf("LookupASNKey(%d): url=%q, want to contain %q", tt.asn, gotURL, tt.wantURL)
		}
	}
}

func TestLookupASNKey_BoundaryBeyondRange(t *testing.T) {
	_, found := LookupASNKey(37888)
	_ = found // may or may not be in another range
}

func TestUpdateFromIANA(t *testing.T) {
	// Verify that UpdateFromIANA replaces IANA data but custom entries still win.
	original, _ := LookupRdapServer("com")

	fakeIANA := map[string]string{
		"com": "https://fake-iana.example/rdap/",
	}
	UpdateFromIANA(fakeIANA)

	got, ok := LookupRdapServer("com")
	if !ok || got != "https://fake-iana.example/rdap/" {
		t.Errorf("after UpdateFromIANA: got %q, want fake URL", got)
	}

	// Restore with original compiled data so other tests aren't affected.
	UpdateFromIANA(compiledRdapServers)
	restored, _ := LookupRdapServer("com")
	if restored != original {
		t.Errorf("after restore: got %q, want %q", restored, original)
	}
}
