package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/handlers"
	"github.com/KincaidYang/whois/internal/serverlist"
	"github.com/KincaidYang/whois/internal/utils"
)

// withFakeRDAP registers a fake RDAP upstream for the given serverlist keys
// (CIDR prefixes or ASN ranges) and restores the built-in index on cleanup.
// The injected prefixes are more specific than any built-in RIR entry, so the
// lookup's rightmost-start binary search always resolves to the fake.
func withFakeRDAP(t *testing.T, h http.HandlerFunc, keys ...string) *httptest.Server {
	t.Helper()
	fake := httptest.NewServer(h)
	entries := make(map[string]string, len(keys))
	for _, k := range keys {
		entries[k] = fake.URL + "/"
	}
	serverlist.UpdateFromIANA(entries)
	t.Cleanup(func() {
		fake.Close()
		serverlist.UpdateFromIANA(nil)
	})
	return fake
}

// TestHandleIPMissAndHit drives a full IP query: cache miss routed to the
// fake upstream, then a second request served from cache.
func TestHandleIPMissAndHit(t *testing.T) {
	// Written by the httptest handler goroutine, read by the test goroutine.
	var gotPath atomic.Value
	withFakeRDAP(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{"objectClassName":"ip network","handle":"NET-ZZIPTEST","startAddress":"192.0.2.128","endAddress":"192.0.2.255"}`))
	}, "192.0.2.128/25")

	req := httptest.NewRequest("GET", "/ip/192.0.2.130", nil)
	w := httptest.NewRecorder()
	newTestMux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("X-Cache: got %q, want MISS", got)
	}
	if got, _ := gotPath.Load().(string); got != "/ip/192.0.2.130" {
		t.Errorf("upstream path: %q", got)
	}
	if !strings.Contains(w.Body.String(), "NET-ZZIPTEST") {
		t.Errorf("body missing upstream data: %s", w.Body.String())
	}

	// Second request must be served from cache without touching upstream.
	w = httptest.NewRecorder()
	newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/ip/192.0.2.130", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("cache hit: expected 200, got %d", w.Code)
	}
	if got := w.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("X-Cache: got %q, want HIT", got)
	}
}

// TestIPSpellingsShareOneCacheEntry verifies equivalent spellings of one
// address resolve to a single canonical cache key and a single upstream
// query, instead of one entry (and one upstream request) per spelling.
func TestIPSpellingsShareOneCacheEntry(t *testing.T) {
	var upstreamHits atomic.Int32
	var gotPath atomic.Value
	withFakeRDAP(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		gotPath.Store(r.URL.Path)
		_, _ = w.Write([]byte(`{"objectClassName":"ip network","handle":"NET-ZZV6TEST","startAddress":"2001:db8:1234::","endAddress":"2001:db8:1234:ffff:ffff:ffff:ffff:ffff"}`))
	}, "2001:db8:1234::/48")

	w := httptest.NewRecorder()
	newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/ip/2001:0DB8:1234:0000:0000:0000:0000:0001", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("X-Cache: got %q, want MISS", got)
	}
	// The upstream query carries the canonical form, not the caller's spelling.
	if got, _ := gotPath.Load().(string); got != "/ip/2001:db8:1234::1" {
		t.Errorf("upstream path: got %q, want the canonical form", got)
	}

	w = httptest.NewRecorder()
	newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/ip/2001:db8:1234::1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("compressed form: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("compressed form X-Cache: got %q, want HIT", got)
	}
	if n := upstreamHits.Load(); n != 1 {
		t.Errorf("upstream was queried %d times, want 1", n)
	}
}

// TestCIDRHostBitsMasked verifies a prefix carrying host bits is queried as
// the network it names (RFC 9082), so /24 queries that differ only in the
// host part share one cache entry.
func TestCIDRHostBitsMasked(t *testing.T) {
	var gotPath atomic.Value
	withFakeRDAP(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		_, _ = w.Write([]byte(`{"objectClassName":"ip network","handle":"NET-ZZCIDRTEST","startAddress":"198.51.100.0","endAddress":"198.51.100.255"}`))
	}, "198.51.100.0/24")

	w := httptest.NewRecorder()
	newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/ip/198.51.100.7/24", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got, _ := gotPath.Load().(string); got != "/ip/198.51.100.0/24" {
		t.Errorf("upstream path: got %q, want the masked network", got)
	}

	w = httptest.NewRecorder()
	newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/ip/198.51.100.0/24", nil))
	if got := w.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("X-Cache: got %q, want HIT", got)
	}
}

// TestHandleIPUpstreamNotFound verifies an upstream 404 is returned as a
// problem response and negative-cached for the next request.
func TestHandleIPUpstreamNotFound(t *testing.T) {
	withFakeRDAP(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}, "192.0.2.128/25")

	w := httptest.NewRecorder()
	newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/ip/192.0.2.140", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}

	// The negative result must be cached: the next request is a 404 cache hit.
	w = httptest.NewRecorder()
	newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/ip/192.0.2.140", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("negative cache hit: expected 404, got %d", w.Code)
	}
	if got := w.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("X-Cache: got %q, want HIT", got)
	}
}

// TestHandleIPNegativeCacheDenied verifies a cached "denied" marker is served
// as 403 without an upstream query.
func TestHandleIPNegativeCacheDenied(t *testing.T) {
	key := handlers.CacheKeyPrefix + "192.0.2.150"
	if err := config.CacheManager.Set(context.Background(), key, "\x00neg:denied", time.Minute); err != nil {
		t.Fatalf("failed to seed cache: %v", err)
	}

	w := httptest.NewRecorder()
	newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/ip/192.0.2.150", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleIPRefresh verifies refresh=true bypasses a stale cache entry and
// overwrites it with the upstream result.
func TestHandleIPRefresh(t *testing.T) {
	withFakeRDAP(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"objectClassName":"ip network","handle":"NET-FRESH","startAddress":"192.0.2.128","endAddress":"192.0.2.255"}`))
	}, "192.0.2.128/25")

	key := handlers.CacheKeyPrefix + "192.0.2.160"
	if err := config.CacheManager.Set(context.Background(), key, `{"handle":"NET-STALE"}`, time.Minute); err != nil {
		t.Fatalf("failed to seed cache: %v", err)
	}

	w := httptest.NewRecorder()
	handlers.HandleIP(context.Background(), w, "192.0.2.160", handlers.CacheKeyPrefix, true)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Cache"); got != "REFRESH" {
		t.Errorf("X-Cache: got %q, want REFRESH", got)
	}
	if !strings.Contains(w.Body.String(), "NET-FRESH") {
		t.Errorf("body should carry the refreshed data: %s", w.Body.String())
	}
}

// TestHandleASNMissAndHit drives a full ASN query against a fake upstream,
// using a range inside the RFC 6996 private 32-bit space that no RIR entry
// covers.
func TestHandleASNMissAndHit(t *testing.T) {
	var gotPath atomic.Value
	withFakeRDAP(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		_, _ = w.Write([]byte(`{"objectClassName":"autnum","handle":"AS-ZZASNTEST","startAutnum":4199999990,"endAutnum":4199999999}`))
	}, "4199999990-4199999999")

	w := httptest.NewRecorder()
	newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/autnum/4199999995", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("X-Cache: got %q, want MISS", got)
	}
	if got, _ := gotPath.Load().(string); got != "/autnum/4199999995" {
		t.Errorf("upstream path: %q", got)
	}
	if !strings.Contains(w.Body.String(), "AS-ZZASNTEST") {
		t.Errorf("body missing upstream data: %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/autnum/as4199999995", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("cache hit: expected 200, got %d", w.Code)
	}
	if got := w.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("X-Cache: got %q, want HIT", got)
	}
}

// TestHandleASNLeadingZeros verifies that different spellings of the same
// ASN ("as4199999995" vs "as04199999995") share one cache entry and one
// upstream call instead of being treated as distinct resources.
func TestHandleASNLeadingZeros(t *testing.T) {
	var upstreamCalls atomic.Int32
	withFakeRDAP(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_, _ = w.Write([]byte(`{"objectClassName":"autnum","handle":"AS-ZZASNTEST","startAutnum":4199999990,"endAutnum":4199999999}`))
	}, "4199999990-4199999999")

	mux := newTestMux()
	for _, path := range []string{"/autnum/as4199999992", "/autnum/as04199999992", "/autnum/as004199999992"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d: %s", path, w.Code, w.Body.String())
		}
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Errorf("upstream calls: got %d, want 1 (leading zeros should not create new cache entries)", got)
	}
}

// TestHandleASNInvalidFormat exercises the handler's own ASN validation
// (routes normally pre-validate, so this calls the handler directly).
func TestHandleASNInvalidFormat(t *testing.T) {
	w := httptest.NewRecorder()
	handlers.HandleASN(context.Background(), w, "asnotanumber", handlers.CacheKeyPrefix, false)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleASNMaxUint32 exercises the top of the 4-byte ASN range (RFC 6793),
// which overflows a 32-bit int and must be handled via uint32 instead so
// behavior does not depend on the build's GOARCH.
func TestHandleASNMaxUint32(t *testing.T) {
	w := httptest.NewRecorder()
	handlers.HandleASN(context.Background(), w, "as4294967295", handlers.CacheKeyPrefix, false)
	if w.Code == http.StatusBadRequest {
		t.Fatalf("max uint32 ASN should parse, got 400: %s", w.Body.String())
	}
}

// TestHandleASNRefresh verifies the refresh path for ASN queries.
func TestHandleASNRefresh(t *testing.T) {
	withFakeRDAP(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"objectClassName":"autnum","handle":"AS-FRESH","startAutnum":4199999990,"endAutnum":4199999999}`))
	}, "4199999990-4199999999")

	w := httptest.NewRecorder()
	handlers.HandleASN(context.Background(), w, "as4199999991", handlers.CacheKeyPrefix, true)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Cache"); got != "REFRESH" {
		t.Errorf("X-Cache: got %q, want REFRESH", got)
	}
}

// TestHandleReadyRequireRedis verifies /ready reports 503 when Redis is
// required but the instance runs on the memory cache. The cache manager is
// swapped to a memory-only instance so the result does not depend on whether
// the machine running the tests happens to have Redis reachable.
func TestHandleReadyRequireRedis(t *testing.T) {
	orig := config.RequireRedis
	origCache := config.CacheManager
	mem := utils.NewMemoryCache(16, time.Minute, 0)
	config.RequireRedis = true
	config.CacheManager = mem
	t.Cleanup(func() {
		config.RequireRedis = orig
		config.CacheManager = origCache
		_ = mem.Close()
	})

	w := httptest.NewRecorder()
	handlers.HandleReady(w, httptest.NewRequest("GET", "/ready", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "redis required but unavailable") {
		t.Errorf("body: %s", w.Body.String())
	}
}

// TestHandleIPAndASNWithoutRegistry verifies that addresses and AS numbers no
// registry answers for (loopback, private, reserved) are reported as
// not-found, like a domain under a TLD with no server, rather than as a
// failed query.
func TestHandleIPAndASNWithoutRegistry(t *testing.T) {
	for _, resource := range []string{"127.0.0.1", "10.0.0.1", "240.0.0.1", "fc00::1", "0.0.0.0/0"} {
		w := httptest.NewRecorder()
		handlers.HandleIP(context.Background(), w, resource, handlers.CacheKeyPrefix, false)
		if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "#not-found") {
			t.Errorf("IP %s: got %d %s, want 404 not-found", resource, w.Code, w.Body.String())
		}
	}
	for _, resource := range []string{"as0", "as64512", "as4200000000"} {
		w := httptest.NewRecorder()
		handlers.HandleASN(context.Background(), w, resource, handlers.CacheKeyPrefix, false)
		if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "#not-found") {
			t.Errorf("ASN %s: got %d %s, want 404 not-found", resource, w.Code, w.Body.String())
		}
	}
}

// TestHandleASNUpstreamErrors covers what the handler does with an upstream
// that answers but not with a usable autnum object: a 404 is not-found, and
// a response describing another AS number is a failed query, not a result.
func TestHandleASNUpstreamErrors(t *testing.T) {
	withFakeRDAP(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/4199999981") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"objectClassName":"autnum","handle":"AS1","startAutnum":1,"endAutnum":1}`))
	}, "4199999980-4199999989")

	for path, want := range map[string]int{
		"/autnum/4199999981": http.StatusNotFound,
		"/autnum/4199999982": http.StatusInternalServerError,
	} {
		w := httptest.NewRecorder()
		newTestMux().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != want {
			t.Errorf("%s: got %d, want %d: %s", path, w.Code, want, w.Body.String())
		}
	}
}

// TestHandleIPUpstreamRateLimited verifies that a registry answering 429 is
// reported as 503 upstream-rate-limited with the registry's Retry-After, and
// that the result is not cached: the next request queries upstream again.
func TestHandleIPUpstreamRateLimited(t *testing.T) {
	var calls atomic.Int32
	withFakeRDAP(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}, "192.0.2.64/27")

	for i := 1; i <= 2; i++ {
		w := httptest.NewRecorder()
		newTestMux().ServeHTTP(w, httptest.NewRequest("GET", "/ip/192.0.2.70", nil))
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "#upstream-rate-limited") {
			t.Fatalf("request %d: got %d %s, want 503 upstream-rate-limited", i, w.Code, w.Body.String())
		}
		if got := w.Header().Get("Retry-After"); got != "30" {
			t.Errorf("request %d: Retry-After = %q, want 30", i, got)
		}
		if got := int(calls.Load()); got != i {
			t.Errorf("request %d: upstream called %d times; a rate-limited answer must not be cached", i, got)
		}
	}
}
