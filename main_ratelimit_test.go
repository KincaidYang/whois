package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/KincaidYang/whois/internal/config"
	"golang.org/x/time/rate"
)

// limitedClient builds an AuthClient with a per-minute rate limit, the same
// way config.normalizeAuthClients does.
func limitedClient(key, name string, perMinute int) config.AuthClient {
	return config.AuthClient{
		Key:       key,
		Name:      name,
		RateLimit: perMinute,
		Limiter:   rate.NewLimiter(rate.Limit(perMinute)/60, perMinute),
	}
}

// TestPerKeyRateLimitExceeded verifies that a key with rateLimit N gets N
// requests through and a 429 with Retry-After on request N+1.
func TestPerKeyRateLimitExceeded(t *testing.T) {
	withTestAuthClients(t, []config.AuthClient{limitedClient("limited-key", "ci", 2)})

	for i := 1; i <= 2; i++ {
		req := httptest.NewRequest("GET", "/info", nil)
		req.Header.Set("X-API-Key", "limited-key")
		if w := authRequest(req); w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i, w.Code)
		}
	}

	req := httptest.NewRequest("GET", "/info", nil)
	req.Header.Set("X-API-Key", "limited-key")
	w := authRequest(req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("request 3: expected 429, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Errorf("expected problem+json, got %q", ct)
	}
	if !strings.Contains(w.Body.String(), "#rate-limited") {
		t.Errorf("body missing rate-limited problem type: %s", w.Body.String())
	}
	retryAfter, err := strconv.Atoi(w.Header().Get("Retry-After"))
	if err != nil || retryAfter < 1 {
		t.Errorf("Retry-After: got %q, want an integer >= 1", w.Header().Get("Retry-After"))
	}
}

// TestPerKeyRateLimitUnlimited verifies keys without a rateLimit are not
// throttled.
func TestPerKeyRateLimitUnlimited(t *testing.T) {
	withTestAuthKeys(t, "free-key")

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("GET", "/info", nil)
		req.Header.Set("X-API-Key", "free-key")
		if w := authRequest(req); w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}
}

// TestPerKeyRateLimitIndependent verifies one key exhausting its budget does
// not affect another key.
func TestPerKeyRateLimitIndependent(t *testing.T) {
	withTestAuthClients(t, []config.AuthClient{
		limitedClient("key-a", "a", 1),
		limitedClient("key-b", "b", 1),
	})

	reqA := httptest.NewRequest("GET", "/info", nil)
	reqA.Header.Set("X-API-Key", "key-a")
	if w := authRequest(reqA); w.Code != http.StatusOK {
		t.Fatalf("key-a first request: expected 200, got %d", w.Code)
	}

	reqA = httptest.NewRequest("GET", "/info", nil)
	reqA.Header.Set("X-API-Key", "key-a")
	if w := authRequest(reqA); w.Code != http.StatusTooManyRequests {
		t.Fatalf("key-a second request: expected 429, got %d", w.Code)
	}

	reqB := httptest.NewRequest("GET", "/info", nil)
	reqB.Header.Set("X-API-Key", "key-b")
	if w := authRequest(reqB); w.Code != http.StatusOK {
		t.Errorf("key-b should be unaffected by key-a's limit: got %d", w.Code)
	}
}
