package utils

import (
	"net"
	"regexp"

	"golang.org/x/net/idna"
)

// Pre-compiled regular expressions shared by the HTTP and MCP entry points so
// both validate input identically.
var (
	asnRegex = regexp.MustCompile(`^(?i)(as|asn)?\d+$`)
	// domainRegex is matched against the ASCII/punycode form (see IsDomain), so
	// the final label may be either an alphabetic TLD or a punycode TLD such as
	// "xn--fiqs8s" (.中国), which contains digits and hyphens.
	domainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9-]+)$`)
)

// IsASN reports whether the given resource is an Autonomous System Number (ASN).
func IsASN(resource string) bool {
	return asnRegex.MatchString(resource)
}

// Resource kinds reported by ClassifyResource. The values double as the "type"
// label on request metrics and as the resource type the RFC 9082-style typed
// paths require, so they must stay stable.
const (
	KindDomain  = "domain"
	KindIP      = "ip"
	KindASN     = "asn"
	KindUnknown = "unknown"
)

// ClassifyResource reports which kind of resource s names, along with the
// canonical form the query should use. It is the single entry-point
// classifier: the HTTP handler, the batch endpoint and the MCP tool all route
// through it so they agree on what a query string means.
//
// IP addresses and prefixes are canonicalized ("2001:0db8:0:0:0:0:0:1" →
// "2001:db8::1", "192.0.2.5/24" → "192.0.2.0/24"), so equivalent spellings of
// one resource share a cache entry and one upstream query instead of one per
// spelling. Masking the host bits off a prefix also matches RFC 9082, which
// defines the ip query as the network rather than an address inside it.
// Domains and ASNs are returned unchanged: HandleDomain applies IDNA and
// public-suffix normalization, HandleASN reduces an ASN to its digits.
func ClassifyResource(s string) (kind, canonical string) {
	if ip := net.ParseIP(s); ip != nil {
		return KindIP, ip.String()
	}
	if _, ipNet, err := net.ParseCIDR(s); err == nil {
		return KindIP, ipNet.String()
	}
	if IsASN(s) {
		return KindASN, s
	}
	if IsDomain(s) {
		return KindDomain, s
	}
	return KindUnknown, s
}

// IsDomain reports whether the given resource is a valid domain name.
// IDN (Unicode) domains such as "müller.de" or "例子.cn" are converted to their
// ASCII/punycode form before validation, matching the conversion HandleDomain
// performs, so they are accepted at the entry point.
func IsDomain(resource string) bool {
	ascii, err := idna.ToASCII(resource)
	if err != nil {
		return false
	}
	return domainRegex.MatchString(ascii)
}
