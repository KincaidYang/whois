package handlers

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.json
var openAPISpec []byte

// HandleOpenAPI serves the embedded OpenAPI 3.1 description of this service.
func HandleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(openAPISpec)
}
