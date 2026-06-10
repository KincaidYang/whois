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

// IsIP reports whether the given resource is a bare IPv4 or IPv6 address.
func IsIP(resource string) bool {
	return net.ParseIP(resource) != nil
}

// IsCIDR reports whether the given resource is an IP prefix in CIDR notation
// (e.g. "192.0.2.0/24", "2001:db8::/32").
func IsCIDR(resource string) bool {
	_, _, err := net.ParseCIDR(resource)
	return err == nil
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
