package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/utils"
)

// setCacheControl tells clients they may cache a successful response for
// maxAge, no longer than the server itself would still consider it fresh.
// When API key authentication is enabled the response is marked private: a
// shared cache (CDN) serving it to other clients would bypass the key check
// and the per-key rate limit.
func setCacheControl(w http.ResponseWriter, maxAge time.Duration) {
	scope := "public"
	if len(config.AuthClients) > 0 {
		scope = "private"
	}
	seconds := int(maxAge.Seconds())
	if seconds < 0 {
		seconds = 0
	}
	w.Header().Set("Cache-Control", fmt.Sprintf("%s, max-age=%d", scope, seconds))
}

// missLabel is the X-Cache value for a response that went upstream: REFRESH
// when the cache was deliberately bypassed (?refresh=1), MISS otherwise.
func missLabel(refresh bool) string {
	if refresh {
		return "REFRESH"
	}
	return "MISS"
}

// cacheOutcome is what the cache lookup at the head of a handler settled.
type cacheOutcome int

const (
	cacheMiss   cacheOutcome = iota // nothing cached; the caller must query upstream
	cacheServed                     // the cached entry, or its negative marker, has been written
	cacheFailed                     // the cache backend failed; an error response has been written
)

// serveFromCache answers a request from the cached entry for key when there is
// one. A refresh query skips the lookup entirely: it asked for a forced
// upstream fetch. Anything other than cacheMiss means the response is already
// written and the handler is done.
func serveFromCache(ctx context.Context, w http.ResponseWriter, key string, refresh bool) cacheOutcome {
	if refresh {
		return cacheMiss
	}

	result, err := utils.GetFromCache(ctx, config.CacheManager, key)
	if err != nil {
		utils.HandleInternalError(ctx, w, err)
		return cacheFailed
	}
	if !result.Found {
		return cacheMiss
	}

	w.Header().Set("X-Cache", "HIT")
	if utils.IsNegativeCacheHit(w, result.Data) {
		return cacheServed
	}
	// A cache entry near the end of its life must not tell the client it's
	// good for another full config.CacheExpiration: that's how a downstream
	// browser/CDN cache ends up holding data fresh well past when the server
	// itself would have refreshed it. ExpiresAt is zero (unknown) only for a
	// Cache implementation that doesn't report it, in which case the full
	// TTL is the only thing left to offer.
	maxAge := config.CacheExpiration
	if !result.ExpiresAt.IsZero() {
		maxAge = time.Until(result.ExpiresAt)
	}
	setCacheControl(w, maxAge)
	utils.HandleCacheResponse(w, result.Data, contentType(result.Data))
	return cacheServed
}

// writeUpstreamResult writes a result that came from an upstream query rather
// than from the cache. It just started its full TTL, so the full
// config.CacheExpiration is the correct max-age, not an approximation.
func writeUpstreamResult(w http.ResponseWriter, outcome queryOutcome, refresh bool) {
	w.Header().Set("X-Cache", missLabel(refresh))
	setCacheControl(w, config.CacheExpiration)
	w.Header().Set("Content-Type", outcome.contentType)
	_, _ = fmt.Fprint(w, outcome.body)
}

// contentType reports how a cached body should be typed. Only ?raw responses
// are not JSON, and they are stored under their own key namespace, so the
// first byte tells the two apart.
func contentType(data string) string {
	if len(data) == 0 || data[0] != '{' {
		return "text/plain; charset=utf-8"
	}
	return "application/json"
}
