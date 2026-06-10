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
	"golang.org/x/net/idna"
)

// TestHandlerUnknownTLD exercises HandleDomain's server-selection logic for a
// syntactically valid domain whose TLD has neither an RDAP nor a WHOIS server.
// This path is network-free.
func TestHandlerUnknownTLD(t *testing.T) {
	req := httptest.NewRequest("GET", "/example.zzqqxxnotld", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "No WHOIS or RDAP server known") {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}

// TestHandlerTextPlainCacheHit verifies that a cached non-JSON payload is served
// as text/plain, covering the content-type sniffing branch in HandleDomain.
func TestHandlerTextPlainCacheHit(t *testing.T) {
	domain := "textplaintest99999.cn"
	key := handlers.CacheKeyPrefix + domain
	cached := "Domain Name: textplaintest99999.cn\nRaw WHOIS text, not JSON\n"
	ctx := context.Background()
	if err := config.CacheManager.Set(ctx, key, cached, time.Minute); err != nil {
		t.Fatalf("failed to seed cache: %v", err)
	}

	req := httptest.NewRequest("GET", "/"+domain, nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("expected text/plain content type, got %q", ct)
	}
	if !strings.Contains(w.Body.String(), "Raw WHOIS text") {
		t.Errorf("response body missing cached content: %s", w.Body.String())
	}
}

// TestHandlerIDNCacheHit confirms a Unicode IDN request is accepted at the entry
// point and resolved against the punycode cache key written by HandleDomain.
func TestHandlerIDNCacheHit(t *testing.T) {
	unicode := "例子idntest.cn"
	punycode, err := idna.ToASCII(unicode)
	if err != nil {
		t.Fatalf("idna.ToASCII: %v", err)
	}
	key := handlers.CacheKeyPrefix + punycode
	cached := `{"ldhName":"` + punycode + `"}`
	ctx := context.Background()
	if err := config.CacheManager.Set(ctx, key, cached, time.Minute); err != nil {
		t.Fatalf("failed to seed cache: %v", err)
	}

	req := httptest.NewRequest("GET", "/"+unicode, nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for IDN input, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), punycode) {
		t.Errorf("response body missing punycode domain: %s", w.Body.String())
	}
}

// TestHandlerNegativeCacheHit verifies a cached negative marker is served as a
// 404 rather than as a normal payload, exercising the read-side interception.
func TestHandlerNegativeCacheHit(t *testing.T) {
	domain := "negativecachetest99999.cn"
	key := handlers.CacheKeyPrefix + domain
	ctx := context.Background()
	// Seed a not-found negative marker (same encoding CacheNegativeResult writes).
	if err := config.CacheManager.Set(ctx, key, "\x00neg:notfound", time.Minute); err != nil {
		t.Fatalf("failed to seed cache: %v", err)
	}

	req := httptest.NewRequest("GET", "/"+domain, nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for negative cache hit, got %d", w.Code)
	}
}

// TestHandlerIPCacheHit confirms the IP branch resolves and serves cached data.
func TestHandlerIPCacheHit(t *testing.T) {
	ip := "192.0.2.1"
	key := handlers.CacheKeyPrefix + ip
	cached := `{"objectClassName":"ip network","handle":"192.0.2.0/24"}`
	ctx := context.Background()
	if err := config.CacheManager.Set(ctx, key, cached, time.Minute); err != nil {
		t.Fatalf("failed to seed cache: %v", err)
	}

	req := httptest.NewRequest("GET", "/"+ip, nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "192.0.2.0/24") {
		t.Errorf("response body missing cached IP data: %s", w.Body.String())
	}
}
