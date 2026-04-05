package server_lists

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ipNetEntry maps a parsed CIDR network to its RDAP server URL.
type ipNetEntry struct {
	net   *net.IPNet
	start []byte // normalized network address bytes (4 bytes for IPv4, 16 for IPv6)
	url   string
}

// asnRangeEntry maps an ASN range to its RDAP server URL.
type asnRangeEntry struct {
	lower int
	upper int
	url   string
}

// serverIndex holds the runtime lookup structures derived from the active server map.
type serverIndex struct {
	servers      map[string]string // full key→URL map (for TLD/domain lookups)
	ipv4NetList  []ipNetEntry      // sorted by start address
	ipv6NetList  []ipNetEntry      // sorted by start address
	asnRangeList []asnRangeEntry   // sorted by lower bound
}

var (
	mu    sync.RWMutex
	index serverIndex
)

func init() {
	merged := mergeServers(compiledRdapServers, customRdapServers)
	index = buildIndex(merged)
}

// mergeServers returns a new map with base entries overlaid by overrides.
func mergeServers(base, overrides map[string]string) map[string]string {
	merged := make(map[string]string, len(base)+len(overrides))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range overrides {
		merged[k] = v
	}
	return merged
}

// UpdateFromIANA rebuilds the active index by merging fetched IANA data with
// the compiled-in baseline (as fallback for missing categories) and custom entries.
// custom always wins; fetched IANA beats compiled baseline.
func UpdateFromIANA(ianaServers map[string]string) {
	// Start from compiled baseline, overlay fetched IANA, then custom on top.
	merged := mergeServers(compiledRdapServers, ianaServers)
	merged = mergeServers(merged, customRdapServers)
	newIndex := buildIndex(merged)

	mu.Lock()
	index = newIndex
	mu.Unlock()
}

// LookupRdapServer returns the RDAP server URL for a given key (TLD, CIDR, ASN range).
func LookupRdapServer(key string) (string, bool) {
	mu.RLock()
	v, ok := index.servers[key]
	mu.RUnlock()
	return v, ok
}

// compareIPs compares two equal-length IP byte slices lexicographically.
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

// buildIndex parses a server map into a serverIndex with sorted lookup structures.
func buildIndex(servers map[string]string) serverIndex {
	idx := serverIndex{
		servers: servers,
	}

	for key, url := range servers {
		if strings.Contains(key, "/") {
			_, ipNet, err := net.ParseCIDR(key)
			if err != nil {
				continue
			}
			if v4 := ipNet.IP.To4(); v4 != nil {
				start := make([]byte, 4)
				copy(start, v4)
				idx.ipv4NetList = append(idx.ipv4NetList, ipNetEntry{net: ipNet, start: start, url: url})
			} else {
				start := make([]byte, 16)
				copy(start, ipNet.IP.To16())
				idx.ipv6NetList = append(idx.ipv6NetList, ipNetEntry{net: ipNet, start: start, url: url})
			}
		} else if strings.Contains(key, "-") {
			parts := strings.SplitN(key, "-", 2)
			lower, err := strconv.Atoi(parts[0])
			if err != nil {
				continue
			}
			upper, err := strconv.Atoi(parts[1])
			if err != nil {
				continue
			}
			idx.asnRangeList = append(idx.asnRangeList, asnRangeEntry{lower: lower, upper: upper, url: url})
		}
	}

	sort.Slice(idx.ipv4NetList, func(i, j int) bool {
		return compareIPs(idx.ipv4NetList[i].start, idx.ipv4NetList[j].start) < 0
	})
	sort.Slice(idx.ipv6NetList, func(i, j int) bool {
		return compareIPs(idx.ipv6NetList[i].start, idx.ipv6NetList[j].start) < 0
	})
	sort.Slice(idx.asnRangeList, func(i, j int) bool {
		return idx.asnRangeList[i].lower < idx.asnRangeList[j].lower
	})

	return idx
}

// binarySearchIP finds the index of the rightmost entry whose start address ≤ ip.
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

// LookupIPKey returns the RDAP server URL for the given IP address.
// Uses binary search on pre-sorted, non-overlapping CIDR lists: O(log n).
func LookupIPKey(ip net.IP) (string, bool) {
	mu.RLock()
	defer mu.RUnlock()

	if v4 := ip.To4(); v4 != nil {
		i := binarySearchIP(index.ipv4NetList, v4)
		if i >= 0 && index.ipv4NetList[i].net.Contains(ip) {
			return index.ipv4NetList[i].url, true
		}
		return "", false
	}

	v6 := ip.To16()
	if v6 == nil {
		return "", false
	}
	i := binarySearchIP(index.ipv6NetList, v6)
	if i >= 0 && index.ipv6NetList[i].net.Contains(ip) {
		return index.ipv6NetList[i].url, true
	}
	return "", false
}

// LookupASNKey returns the RDAP server URL for the given ASN number.
// Uses binary search on the pre-sorted range list.
func LookupASNKey(asn int) (string, bool) {
	mu.RLock()
	defer mu.RUnlock()

	lo, hi, idx := 0, len(index.asnRangeList)-1, -1
	for lo <= hi {
		mid := (lo + hi) / 2
		if index.asnRangeList[mid].lower <= asn {
			idx = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if idx >= 0 && asn <= index.asnRangeList[idx].upper {
		return index.asnRangeList[idx].url, true
	}
	return "", false
}
