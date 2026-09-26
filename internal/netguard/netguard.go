// Package netguard keeps outbound upstream connections (RDAP, WHOIS, IANA
// bootstrap) away from addresses no public registry uses.
//
// The upstream hosts come from trusted tables, but what they resolve to and
// where an RDAP server redirects are not under this service's control: a
// compromised or misconfigured registry, a poisoned resolver or a hostile
// redirect could otherwise point a query at loopback, a private network or a
// cloud metadata endpoint. The check runs in the dialer's Control hook, on
// the address actually being connected to after resolution, so it also holds
// against DNS rebinding.
package netguard

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync/atomic"
	"syscall"
)

// ErrBlockedAddress is returned when an upstream connection or redirect
// targets an address this package refuses.
var ErrBlockedAddress = errors.New("upstream address not allowed")

// maxRedirects bounds how many redirects an upstream request follows. RDAP
// servers redirect rarely and briefly; Go's default of 10 is more rope than
// any legitimate chain needs.
const maxRedirects = 5

// allowPrivate disables the address check. Only tests set it, to talk to
// local httptest and TCP servers.
var allowPrivate atomic.Bool

// SetAllowPrivateForTesting turns the address check off (true) or back on.
// It exists for tests that run upstream stand-ins on loopback; production
// code never calls it.
func SetAllowPrivateForTesting(allow bool) {
	allowPrivate.Store(allow)
}

// metadataAddrs are cloud instance metadata endpoints outside the ranges
// blocked() refuses wholesale. Alibaba Cloud ECS serves metadata (including
// instance credentials) at 100.100.100.200, inside the CGNAT range left open
// below. The other major clouds use link-local (169.254.169.254, Tencent's
// 169.254.0.23) or ULA (AWS fd00:ec2::254) addresses, already covered.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("100.100.100.200"),
}

// blocked reports whether a is an address no public registry is reachable
// at. 100.64.0.0/10 and 198.18.0.0/15 are otherwise deliberately allowed:
// fake-IP DNS modes of common proxy tools (Clash, Surge) resolve every name
// into them, and blocking those would break such deployments outright.
func blocked(a netip.Addr) bool {
	a = a.Unmap()
	if slices.Contains(metadataAddrs, a) {
		return true
	}
	return a.IsLoopback() ||
		a.IsPrivate() ||
		a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() ||
		a.IsMulticast() ||
		a.IsUnspecified()
}

// Control is a net.Dialer Control hook refusing connections to blocked
// addresses. address is the resolved "ip:port" being dialed.
func Control(_, address string, _ syscall.RawConn) error {
	if allowPrivate.Load() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %q: %w", ErrBlockedAddress, address, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: %q: %w", ErrBlockedAddress, address, err)
	}
	if blocked(addr) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, addr)
	}
	return nil
}

// CheckRedirect is an http.Client CheckRedirect policy for upstream
// requests: at most maxRedirects hops, never from https down to http, and
// never to a literal blocked IP. (Hostnames are checked at dial time by
// Control; a proxied client, whose target the proxy resolves, gets only the
// literal-IP check.)
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect from https to %s://%s", req.URL.Scheme, req.URL.Host)
	}
	if allowPrivate.Load() {
		return nil
	}
	if addr, err := netip.ParseAddr(req.URL.Hostname()); err == nil && blocked(addr) {
		return fmt.Errorf("%w: redirect to %s", ErrBlockedAddress, addr)
	}
	return nil
}
