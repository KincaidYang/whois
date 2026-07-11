package handlers

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/utils"
)

//go:embed openapi.json
var openAPISpec []byte

// servedOpenAPI returns the spec bytes and ETag this instance serves. The
// embedded document declares anonymous, bearer and API-key access as
// alternatives (auth is a deployment choice unknown at build time); when this
// instance enforces authentication, the anonymous alternative is dropped so a
// generated client knows a credential is required rather than merely
// possible. Computed once on first use: configuration is loaded before the
// server accepts requests and cannot change at runtime.
var servedOpenAPI = sync.OnceValues(func() ([]byte, string) {
	spec := openAPISpec
	if len(config.AuthClients) > 0 {
		patched, err := withoutAnonymousSecurity(spec)
		if err != nil {
			// Serve the embedded document rather than breaking the endpoint.
			slog.Warn("could not drop anonymous security from OpenAPI spec", "err", err)
		} else {
			spec = patched
		}
	}
	return spec, utils.ETagFor(spec)
})

// withoutAnonymousSecurity removes the empty (anonymous) requirement from the
// document's top-level security array. Only the top level is re-marshaled;
// every other member keeps its embedded bytes.
func withoutAnonymousSecurity(spec []byte) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(spec, &doc); err != nil {
		return nil, err
	}
	rawSecurity, ok := doc["security"]
	if !ok {
		return nil, fmt.Errorf("spec has no top-level security member")
	}
	var security []map[string]json.RawMessage
	if err := json.Unmarshal(rawSecurity, &security); err != nil {
		return nil, err
	}
	filtered := security[:0]
	for _, alternative := range security {
		if len(alternative) > 0 {
			filtered = append(filtered, alternative)
		}
	}
	if len(filtered) == len(security) {
		return nil, fmt.Errorf("spec declares no anonymous security alternative")
	}
	patchedSecurity, err := json.Marshal(filtered)
	if err != nil {
		return nil, err
	}
	doc["security"] = patchedSecurity
	return json.MarshalIndent(doc, "", "  ")
}

// HandleOpenAPI serves the OpenAPI 3.1 description of this service, honouring
// If-None-Match revalidation.
func HandleOpenAPI(w http.ResponseWriter, r *http.Request) {
	spec, etag := servedOpenAPI()
	w.Header().Set("ETag", etag)
	scope := "public"
	if len(config.AuthClients) > 0 {
		scope = "private"
	}
	w.Header().Set("Cache-Control", scope+", max-age=86400")
	if utils.ETagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(spec)
}
