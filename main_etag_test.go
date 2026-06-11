package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/handlers"
)

// TestETagRoundTrip verifies a 200 query response carries an ETag and a
// follow-up request with If-None-Match gets 304 with no body.
func TestETagRoundTrip(t *testing.T) {
	domain := "etagtest99999.cn"
	key := handlers.CacheKeyPrefix + domain
	cached := `{"objectClassName":"domain","ldhName":"etagtest99999.cn"}`
	if err := config.CacheManager.Set(context.Background(), key, cached, time.Minute); err != nil {
		t.Fatalf("failed to seed cache: %v", err)
	}
	mux := newTestMux()

	req := httptest.NewRequest("GET", "/"+domain, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", w.Code)
	}
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("200 response missing ETag header")
	}

	// Revalidate with the returned tag: 304, no body, tag still present.
	req = httptest.NewRequest("GET", "/"+domain, nil)
	req.Header.Set("If-None-Match", etag)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotModified {
		t.Fatalf("revalidation: expected 304, got %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("304 carried a body: %q", w.Body.String())
	}
	if got := w.Header().Get("ETag"); got != etag {
		t.Errorf("304 ETag: got %q, want %q", got, etag)
	}
	if cc := w.Header().Get("Cache-Control"); cc == "" {
		t.Error("304 missing Cache-Control")
	}

	// A stale tag still gets the full body.
	req = httptest.NewRequest("GET", "/"+domain, nil)
	req.Header.Set("If-None-Match", `"stale"`)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("stale tag: expected 200, got %d", w.Code)
	}
	if w.Body.Len() == 0 {
		t.Error("stale tag: body missing")
	}
}

// TestETagAbsentOnError verifies error responses carry no ETag even when the
// client sent If-None-Match.
func TestETagAbsentOnError(t *testing.T) {
	req := httptest.NewRequest("GET", "/not_a_valid_input!!", nil)
	req.Header.Set("If-None-Match", "*")
	w := httptest.NewRecorder()
	newTestMux().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if etag := w.Header().Get("ETag"); etag != "" {
		t.Errorf("error response carried an ETag: %q", etag)
	}
}

// TestOpenAPIETag verifies /openapi.json supports If-None-Match revalidation.
func TestOpenAPIETag(t *testing.T) {
	mux := newTestMux()

	req := httptest.NewRequest("GET", "/openapi.json", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("/openapi.json missing ETag header")
	}

	req = httptest.NewRequest("GET", "/openapi.json", nil)
	req.Header.Set("If-None-Match", etag)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotModified {
		t.Fatalf("revalidation: expected 304, got %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("304 carried a body: %q", w.Body.String())
	}
}
