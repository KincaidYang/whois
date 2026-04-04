package server_lists

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

// ipNetEntry maps a parsed CIDR network to its RDAP server map key.
type ipNetEntry struct {
	net *net.IPNet
	key string // original CIDR string key in TLDToRdapServer
}

// asnRangeEntry maps an ASN range to its RDAP server map key.
type asnRangeEntry struct {
	lower int
	upper int
	key   string // original range string key in TLDToRdapServer
}

var (
	ipNetList   []ipNetEntry
	asnRangeList []asnRangeEntry
)

func init() {
	for key := range TLDToRdapServer {
		if strings.Contains(key, "/") {
			// CIDR entry (IPv4 or IPv6)
			_, ipNet, err := net.ParseCIDR(key)
			if err != nil {
				continue
			}
			ipNetList = append(ipNetList, ipNetEntry{net: ipNet, key: key})
		} else if strings.Contains(key, "-") {
			// Potential ASN range entry (e.g. "1-1876")
			parts := strings.SplitN(key, "-", 2)
			lower, err := strconv.Atoi(parts[0])
			if err != nil {
				continue
			}
			upper, err := strconv.Atoi(parts[1])
			if err != nil {
				continue
			}
			asnRangeList = append(asnRangeList, asnRangeEntry{lower: lower, upper: upper, key: key})
		}
	}

	// Sort ASN ranges by lower bound for binary search
	sort.Slice(asnRangeList, func(i, j int) bool {
		return asnRangeList[i].lower < asnRangeList[j].lower
	})
}

// LookupIPKey returns the TLDToRdapServer map key for the given IP address.
// Returns ("", false) if no matching CIDR is found.
func LookupIPKey(ip net.IP) (string, bool) {
	for _, entry := range ipNetList {
		if entry.net.Contains(ip) {
			return entry.key, true
		}
	}
	return "", false
}

// LookupASNKey returns the TLDToRdapServer map key for the given ASN number.
// Uses binary search on the pre-sorted range list.
// Returns ("", false) if no matching range is found.
func LookupASNKey(asn int) (string, bool) {
	// Find the largest lower bound ≤ asn
	lo, hi, idx := 0, len(asnRangeList)-1, -1
	for lo <= hi {
		mid := (lo + hi) / 2
		if asnRangeList[mid].lower <= asn {
			idx = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if idx >= 0 && asn <= asnRangeList[idx].upper {
		return asnRangeList[idx].key, true
	}
	return "", false
}
