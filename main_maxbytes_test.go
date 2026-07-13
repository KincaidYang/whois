package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KincaidYang/whois/internal/config"
)

// TestMaxBytes verifies the body-size wrapper: requests under the cap pass
// through untouched, oversized ones fail at read time so a handler can never
// buffer an unbounded body.
func TestMaxBytes(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	h := maxBytes(inner, 8)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/mcp", strings.NewReader("small")))
	if w.Code != http.StatusOK {
		t.Errorf("body under limit: got %d, want 200", w.Code)
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/mcp", strings.NewReader("definitely more than eight bytes")))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("body over limit: got %d, want 413", w.Code)
	}
}

// TestBatchHandlerConcurrencyLimit verifies /batch competes for the same
// concurrency slots as single queries and is rejected with 429 when they are
// exhausted.
func TestBatchHandlerConcurrencyLimit(t *testing.T) {
	n := cap(config.ConcurrencyLimiter)
	for i := 0; i < n; i++ {
		config.ConcurrencyLimiter <- struct{}{}
	}
	defer func() {
		for i := 0; i < n; i++ {
			<-config.ConcurrencyLimiter
		}
	}()

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`{"queries":["example.com"]}`))
	w := httptest.NewRecorder()
	batchHandler(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 with concurrency slots exhausted, got %d", w.Code)
	}
}
