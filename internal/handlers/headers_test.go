package handlers

import (
	"context"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/utils"
)

// TestSetCacheControlScope verifies responses are publicly cacheable on an
// open instance but marked private once API key authentication is enabled,
// so a shared cache cannot serve authenticated results past the key check.
func TestSetCacheControlScope(t *testing.T) {
	oldClients := config.AuthClients
	t.Cleanup(func() { config.AuthClients = oldClients })

	config.AuthClients = nil
	w := httptest.NewRecorder()
	setCacheControl(w, time.Hour)
	if cc := w.Header().Get("Cache-Control"); !strings.HasPrefix(cc, "public, max-age=") {
		t.Errorf("open instance: Cache-Control = %q, want public, max-age=...", cc)
	}

	config.AuthClients = []config.AuthClient{{Name: "test", Key: "k"}}
	w = httptest.NewRecorder()
	setCacheControl(w, time.Hour)
	if cc := w.Header().Get("Cache-Control"); !strings.HasPrefix(cc, "private, max-age=") {
		t.Errorf("authenticated instance: Cache-Control = %q, want private, max-age=...", cc)
	}
}

// TestSetCacheControlMaxAgeClamped verifies a negative remaining TTL (an
// entry read just as it expires) is clamped to 0 rather than emitting a
// negative max-age.
func TestSetCacheControlMaxAgeClamped(t *testing.T) {
	oldClients := config.AuthClients
	t.Cleanup(func() { config.AuthClients = oldClients })
	config.AuthClients = nil

	w := httptest.NewRecorder()
	setCacheControl(w, -5*time.Second)
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=0" {
		t.Errorf("Cache-Control = %q, want public, max-age=0", cc)
	}
}

// TestServeFromCacheUsesRemainingTTL verifies a cache hit near the end of
// its life advertises a max-age close to what's actually left, not the
// full config.CacheExpiration — otherwise a downstream browser/CDN cache
// would hold the entry fresh well past when the server itself refreshes it.
func TestServeFromCacheUsesRemainingTTL(t *testing.T) {
	oldManager, oldExpiration, oldClients := config.CacheManager, config.CacheExpiration, config.AuthClients
	t.Cleanup(func() {
		config.CacheManager, config.CacheExpiration, config.AuthClients = oldManager, oldExpiration, oldClients
	})
	config.AuthClients = nil
	config.CacheExpiration = time.Hour // the full TTL a fresh write would get

	mc := utils.NewMemoryCache(10, time.Minute, 0)
	t.Cleanup(func() { _ = mc.Close() })
	config.CacheManager = mc

	ctx := context.Background()
	// Only 10 seconds left on this entry, far less than the full hour
	// config.CacheExpiration would suggest.
	if err := mc.Set(ctx, "k", `{"a":1}`, 10*time.Second); err != nil {
		t.Fatalf("Set: %v", err)
	}

	w := httptest.NewRecorder()
	if outcome := serveFromCache(ctx, w, "k", false); outcome != cacheServed {
		t.Fatalf("serveFromCache = %v, want cacheServed", outcome)
	}

	cc := w.Header().Get("Cache-Control")
	const prefix = "public, max-age="
	if !strings.HasPrefix(cc, prefix) {
		t.Fatalf("Cache-Control = %q, want prefix %q", cc, prefix)
	}
	maxAge, err := strconv.Atoi(strings.TrimPrefix(cc, prefix))
	if err != nil {
		t.Fatalf("could not parse max-age from %q: %v", cc, err)
	}
	if maxAge < 5 || maxAge > 10 {
		t.Errorf("max-age = %d, want close to the entry's remaining 10s TTL, not the full %ds config.CacheExpiration",
			maxAge, int(config.CacheExpiration.Seconds()))
	}
}
