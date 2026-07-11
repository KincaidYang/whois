package handlers

import (
	"fmt"
	"net/http"

	"github.com/KincaidYang/whois/internal/config"
)

// setCacheControl tells clients they may cache a successful response for as
// long as the server itself caches it. When API key authentication is
// enabled the response is marked private: a shared cache (CDN) serving it
// to other clients would bypass the key check and the per-key rate limit.
func setCacheControl(w http.ResponseWriter) {
	scope := "public"
	if len(config.AuthClients) > 0 {
		scope = "private"
	}
	w.Header().Set("Cache-Control", fmt.Sprintf("%s, max-age=%d", scope, int(config.CacheExpiration.Seconds())))
}

// missLabel is the X-Cache value for a response that went upstream: REFRESH
// when the cache was deliberately bypassed (?refresh=1), MISS otherwise.
func missLabel(refresh bool) string {
	if refresh {
		return "REFRESH"
	}
	return "MISS"
}
