package handlers

import "testing"

// TestIcannSuffix covers the PSL-private-section climb: a private entry
// (blogspot.com, github.io, cn.com) must resolve to the nearest ICANN
// suffix above it, an already-ICANN suffix (including compound ones like
// co.jp) must pass through unchanged, and a name under a TLD absent from
// the list entirely (icann=false with nothing further to climb) must be
// returned as-is.
func TestIcannSuffix(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"test.blogspot.com", "com"},
		{"blogspot.com", "com"},
		{"myblog.github.io", "io"},
		{"example.cn.com", "com"},
		{"example.com", "com"},
		{"test.co.jp", "co.jp"},
		{"co.jp", "co.jp"},
		{"a.b.newtldxyz", "newtldxyz"},
	}
	for _, tt := range tests {
		if got := icannSuffix(tt.name); got != tt.want {
			t.Errorf("icannSuffix(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// TestRegistrableDomain covers deriving the registrable name one label
// above a given suffix, including the suffix-queried-on-its-own case.
func TestRegistrableDomain(t *testing.T) {
	tests := []struct {
		name string
		tld  string
		want string
	}{
		{"test.blogspot.com", "com", "blogspot.com"},
		{"blogspot.com", "com", "blogspot.com"},
		{"myblog.github.io", "io", "github.io"},
		{"example.cn.com", "com", "cn.com"},
		{"example.com", "com", "example.com"},
		{"com", "com", "com"},
		{"deep.sub.example.com", "com", "example.com"},
		{"test.co.jp", "co.jp", "test.co.jp"},
	}
	for _, tt := range tests {
		if got := registrableDomain(tt.name, tt.tld); got != tt.want {
			t.Errorf("registrableDomain(%q, %q) = %q, want %q", tt.name, tt.tld, got, tt.want)
		}
	}
}

// TestRegistrableDomainTLDNotASuffix covers the defensive fallback: a tld
// that (contrary to how the function is actually called, with tld always
// derived from name itself) isn't a suffix of name at all must return name
// unchanged rather than produce a nonsensical result.
func TestRegistrableDomainTLDNotASuffix(t *testing.T) {
	if got := registrableDomain("example.com", "org"); got != "example.com" {
		t.Errorf("registrableDomain(%q, %q) = %q, want the input unchanged", "example.com", "org", got)
	}
}
