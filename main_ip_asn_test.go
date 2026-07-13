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
		_, _ = w.Write([]byte(`{"objectClassName":"ip network","handle":"NET-FRESH"}`))
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
		_, _ = w.Write([]byte(`{"objectClassName":"autnum","handle":"AS-ZZASNTEST"}`))
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

// TestHandleASNInvalidFormat exercises the handler's own ASN validation
// (routes normally pre-validate, so this calls the handler directly).
func TestHandleASNInvalidFormat(t *testing.T) {
	w := httptest.NewRecorder()
	handlers.HandleASN(context.Background(), w, "asnotanumber", handlers.CacheKeyPrefix, false)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleASNRefresh verifies the refresh path for ASN queries.
func TestHandleASNRefresh(t *testing.T) {
	withFakeRDAP(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"objectClassName":"autnum","handle":"AS-FRESH"}`))
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
	mem := utils.NewMemoryCache(16, time.Minute)
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
