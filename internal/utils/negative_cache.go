package utils

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// negativeCachePrefix marks a cache entry as a cached negative result. The
// leading NUL byte cannot appear at the start of a real WHOIS/RDAP payload
// (JSON starts with '{', WHOIS text with printable characters), so it is safe
// to distinguish negative markers from genuine cached data.
const negativeCachePrefix = "\x00neg:"

// Negative result kinds, encoded after the prefix.
const (
	negNotFound = "notfound"
	negDenied   = "denied"
)

// negativeKindForError maps an error to a negative cache kind. Only stable
// "not found" / "denied" outcomes are cacheable; transient errors (network,
// parse failures) return ok=false so they are retried on the next request.
func negativeKindForError(err error) (kind string, ok bool) {
	switch {
	case errors.Is(err, ErrResourceNotFound), errors.Is(err, ErrDomainNotFound):
		return negNotFound, true
	case errors.Is(err, ErrQueryDenied):
		return negDenied, true
	default:
		return "", false
	}
}

// IsNegativeCacheHit reports whether cached data is a negative marker and, if
// so, writes the corresponding HTTP error response. Callers use it on a cache
// hit before treating the data as a real payload.
func IsNegativeCacheHit(w http.ResponseWriter, data string) bool {
	if !strings.HasPrefix(data, negativeCachePrefix) {
		return false
	}
	switch strings.TrimPrefix(data, negativeCachePrefix) {
	case negDenied:
		HandleHTTPError(w, ErrorTypeForbidden, "The registry denied the query")
	default:
		HandleHTTPError(w, ErrorTypeNotFound, "Resource not found")
	}
	return true
}

// CacheNegativeResult stores a short-TTL negative marker for a cacheable
// not-found / denied error, so repeated lookups of a missing resource do not
// hammer upstream servers. Transient errors and non-positive TTLs are ignored.
// Write failures are intentionally swallowed: negative caching is best-effort.
func CacheNegativeResult(ctx context.Context, cache Cache, key string, err error, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	kind, ok := negativeKindForError(err)
	if !ok {
		return
	}
	_ = cache.Set(ctx, key, negativeCachePrefix+kind, ttl)
}
