package handlers

import (
	"fmt"
	"net/http"

	"github.com/KincaidYang/whois/internal/config"
)

// setCacheControl tells clients they may cache a successful response for as
// long as the server itself caches it.
func setCacheControl(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(config.CacheExpiration.Seconds())))
}
