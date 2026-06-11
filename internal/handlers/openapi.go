package handlers

import (
	_ "embed"
	"net/http"

	"github.com/KincaidYang/whois/internal/utils"
)

//go:embed openapi.json
var openAPISpec []byte

// openAPIETag is computed once: the spec is embedded and immutable.
var openAPIETag = utils.ETagFor(openAPISpec)

// HandleOpenAPI serves the embedded OpenAPI 3.1 description of this service,
// honouring If-None-Match revalidation.
func HandleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("ETag", openAPIETag)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	if utils.ETagMatches(r.Header.Get("If-None-Match"), openAPIETag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(openAPISpec)
}
