package utils

import (
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
