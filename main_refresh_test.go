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

// TestRefreshRequiresAuth verifies ?refresh is rejected with the
// refresh-requires-auth problem when authentication is not enabled.
func TestRefreshRequiresAuth(t *testing.T) {
	withTestAuthKeys(t) // auth disabled

	req := httptest.NewRequest("GET", "/example.com?refresh=1", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Errorf("expected problem+json, got %q", ct)
	}
	if !strings.Contains(w.Body.String(), "#refresh-requires-auth") {
		t.Errorf("body missing refresh-requires-auth problem type: %s", w.Body.String())
	}
}

// TestRefreshOptOut verifies refresh=0 / refresh=false behave like no refresh
// at all: served from cache even on an open instance.
func TestRefreshOptOut(t *testing.T) {
	withTestAuthKeys(t) // auth disabled

	domain := "refreshoptouttest.cn"
	key := handlers.CacheKeyPrefix + domain
	if err := config.CacheManager.Set(context.Background(), key, `{"ldhName":"`+domain+`"}`, time.Minute); err != nil {
		t.Fatalf("failed to seed cache: %v", err)
	}

	for _, q := range []string{"?refresh=0", "?refresh=false"} {
		req := httptest.NewRequest("GET", "/"+domain+q, nil)
		w := httptest.NewRecorder()
		handler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", q, w.Code)
		}
		if got := w.Header().Get("X-Cache"); got != "HIT" {
			t.Errorf("%s: X-Cache: got %q, want HIT", q, got)
		}
	}
}

// TestRefreshBypassesCache verifies an authenticated ?refresh skips the cache
// read. The domain's TLD has no WHOIS/RDAP server, so the cached entry is the
// only thing that could serve a 200: without refresh the seeded cache answers
// (HIT); with refresh the handler must go upstream and fails with the
// "no server known" 500 — proving the cache was bypassed, without network.
func TestRefreshBypassesCache(t *testing.T) {
	withTestAuthKeys(t, "refresh-test-key")

	domain := "refreshbypasstest.zzqqxxnotld"
	key := handlers.CacheKeyPrefix + domain
	if err := config.CacheManager.Set(context.Background(), key, `{"ldhName":"`+domain+`"}`, time.Minute); err != nil {
		t.Fatalf("failed to seed cache: %v", err)
	}

	req := httptest.NewRequest("GET", "/"+domain, nil)
	req.Header.Set("X-API-Key", "refresh-test-key")
	w := authRequest(req)
	if w.Code != http.StatusOK || w.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("without refresh: expected cached 200 HIT, got %d %q", w.Code, w.Header().Get("X-Cache"))
	}

	req = httptest.NewRequest("GET", "/"+domain+"?refresh=1", nil)
	req.Header.Set("X-API-Key", "refresh-test-key")
	w = authRequest(req)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "No WHOIS or RDAP server known") {
		t.Errorf("with refresh: expected the upstream path (500 no server known), got %d: %s", w.Code, w.Body.String())
	}
}
