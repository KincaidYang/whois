package server_lists

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

// ipNetEntry maps a parsed CIDR network to its RDAP server map key.
type ipNetEntry struct {
	net   *net.IPNet
	start []byte // normalized network address bytes (4 bytes for IPv4, 16 for IPv6)
	key   string // original CIDR string key in TLDToRdapServer
}

// asnRangeEntry maps an ASN range to its RDAP server map key.
type asnRangeEntry struct {
	lower int
	upper int
	key   string // original range string key in TLDToRdapServer
}

var (
	ipv4NetList  []ipNetEntry  // sorted by start address
	ipv6NetList  []ipNetEntry  // sorted by start address
	asnRangeList []asnRangeEntry
)

// compareIPs compares two equal-length IP byte slices lexicographically.
// Returns negative, zero, or positive.
func compareIPs(a, b []byte) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func init() {
	for key := range TLDToRdapServer {
		if strings.Contains(key, "/") {
			// CIDR entry (IPv4 or IPv6)
			_, ipNet, err := net.ParseCIDR(key)
			if err != nil {
				continue
			}
			if v4 := ipNet.IP.To4(); v4 != nil {
				start := make([]byte, 4)
				copy(start, v4)
				ipv4NetList = append(ipv4NetList, ipNetEntry{net: ipNet, start: start, key: key})
			} else {
				start := make([]byte, 16)
				copy(start, ipNet.IP.To16())
				ipv6NetList = append(ipv6NetList, ipNetEntry{net: ipNet, start: start, key: key})
			}
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

	// Sort IPv4 and IPv6 lists by start address for binary search
	sort.Slice(ipv4NetList, func(i, j int) bool {
		return compareIPs(ipv4NetList[i].start, ipv4NetList[j].start) < 0
	})
	sort.Slice(ipv6NetList, func(i, j int) bool {
		return compareIPs(ipv6NetList[i].start, ipv6NetList[j].start) < 0
	})

	// Sort ASN ranges by lower bound for binary search
	sort.Slice(asnRangeList, func(i, j int) bool {
		return asnRangeList[i].lower < asnRangeList[j].lower
	})
}

// binarySearchIP finds the index of the rightmost entry whose start address ≤ ip.
// Returns -1 if none found.
func binarySearchIP(list []ipNetEntry, ip []byte) int {
	lo, hi, idx := 0, len(list)-1, -1
	for lo <= hi {
		mid := (lo + hi) / 2
		if compareIPs(list[mid].start, ip) <= 0 {
			idx = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return idx
}

// LookupIPKey returns the TLDToRdapServer map key for the given IP address.
// Uses binary search on pre-sorted, non-overlapping CIDR lists: O(log n) per lookup.
// Returns ("", false) if no matching CIDR is found.
func LookupIPKey(ip net.IP) (string, bool) {
	if v4 := ip.To4(); v4 != nil {
		idx := binarySearchIP(ipv4NetList, v4)
		if idx >= 0 && ipv4NetList[idx].net.Contains(ip) {
			return ipv4NetList[idx].key, true
		}
		return "", false
	}

	v6 := ip.To16()
	if v6 == nil {
		return "", false
	}
	idx := binarySearchIP(ipv6NetList, v6)
	if idx >= 0 && ipv6NetList[idx].net.Contains(ip) {
		return ipv6NetList[idx].key, true
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
