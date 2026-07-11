package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KincaidYang/whois/internal/config"
)

// TestSetCacheControlScope verifies responses are publicly cacheable on an
// open instance but marked private once API key authentication is enabled,
// so a shared cache cannot serve authenticated results past the key check.
func TestSetCacheControlScope(t *testing.T) {
	oldClients := config.AuthClients
	t.Cleanup(func() { config.AuthClients = oldClients })

	config.AuthClients = nil
	w := httptest.NewRecorder()
	setCacheControl(w)
	if cc := w.Header().Get("Cache-Control"); !strings.HasPrefix(cc, "public, max-age=") {
		t.Errorf("open instance: Cache-Control = %q, want public, max-age=...", cc)
	}

	config.AuthClients = []config.AuthClient{{Name: "test", Key: "k"}}
	w = httptest.NewRecorder()
	setCacheControl(w)
	if cc := w.Header().Get("Cache-Control"); !strings.HasPrefix(cc, "private, max-age=") {
		t.Errorf("authenticated instance: Cache-Control = %q, want private, max-age=...", cc)
	}
}
