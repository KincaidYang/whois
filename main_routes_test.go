package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/handlers"
)

// newTestMux builds the same routing table main() installs, on a private mux.
func newTestMux() *http.ServeMux {
	mux := http.NewServeMux()
	registerRoutes(mux)
	return mux
}

// TestTypedPathMismatch verifies each typed path rejects resources of the
// wrong type with a 400 problem response.
func TestTypedPathMismatch(t *testing.T) {
	mux := newTestMux()
	for _, path := range []string{
		"/domain/192.0.2.1",
		"/domain/as13335",
		"/ip/example.com",
		"/ip/as13335",
		"/autnum/example.com",
		"/autnum/192.0.2.1",
	} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d", path, w.Code)
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
			t.Errorf("%s: expected problem+json, got %q", path, ct)
		}
	}
}

// TestTypedPathIPCacheHit verifies /ip/ resolves the same cache entries as
// the auto-detecting root path.
func TestTypedPathIPCacheHit(t *testing.T) {
	ip := "192.0.2.77"
	key := handlers.CacheKeyPrefix + ip
	cached := `{"objectClassName":"ip network","handle":"192.0.2.0/24"}`
	if err := config.CacheManager.Set(context.Background(), key, cached, time.Minute); err != nil {
		t.Fatalf("failed to seed cache: %v", err)
	}

	req := httptest.NewRequest("GET", "/ip/"+ip, nil)
	w := httptest.NewRecorder()
	newTestMux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "192.0.2.0/24") {
		t.Errorf("response body missing cached data: %s", w.Body.String())
	}
	if got := w.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("X-Cache: got %q, want HIT", got)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.HasPrefix(cc, "public, max-age=") {
		t.Errorf("Cache-Control: got %q", cc)
	}
}

// TestTypedPathAutnumCacheHit verifies /autnum/ accepts both bare and
// AS-prefixed numbers and resolves the shared cache key.
func TestTypedPathAutnumCacheHit(t *testing.T) {
	key := handlers.CacheKeyPrefix + "64511"
	cached := `{"objectClassName":"autnum","handle":"AS64511"}`
	if err := config.CacheManager.Set(context.Background(), key, cached, time.Minute); err != nil {
		t.Fatalf("failed to seed cache: %v", err)
	}

	for _, path := range []string{"/autnum/64511", "/autnum/as64511", "/autnum/AS64511"} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		newTestMux().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("%s: expected 200, got %d", path, w.Code)
			continue
		}
		if !strings.Contains(w.Body.String(), "AS64511") {
			t.Errorf("%s: response body missing cached data: %s", path, w.Body.String())
		}
	}
}

// TestTypedPathDomainUnknownTLD verifies /domain/ reaches the domain handler
// (network-free no-server branch).
func TestTypedPathDomainUnknownTLD(t *testing.T) {
	req := httptest.NewRequest("GET", "/domain/example.zzqqxxnotld", nil)
	w := httptest.NewRecorder()
	newTestMux().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "No WHOIS or RDAP server known") {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}

// TestCORSPreflight verifies OPTIONS requests are answered by the CORS
// middleware without reaching the query handler.
func TestCORSPreflight(t *testing.T) {
	req := httptest.NewRequest("OPTIONS", "/example.com", nil)
	req.Header.Set("Origin", "https://example.org")
	w := httptest.NewRecorder()
	withCORS(newTestMux()).ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin: got %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "GET") {
		t.Errorf("Access-Control-Allow-Methods: got %q", got)
	}
}

// TestCORSHeaderOnResponse verifies normal responses carry the CORS headers.
func TestCORSHeaderOnResponse(t *testing.T) {
	req := httptest.NewRequest("GET", "/not_a_valid_input!!", nil)
	w := httptest.NewRecorder()
	withCORS(newTestMux()).ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin: got %q", got)
	}
	if got := w.Header().Get("Access-Control-Expose-Headers"); !strings.Contains(got, "X-Cache") {
		t.Errorf("Access-Control-Expose-Headers: got %q", got)
	}
}
