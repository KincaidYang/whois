package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/utils"
)

// TestRequestIDGenerated verifies the middleware generates an ID when the
// client sends none, echoes it on the response, and stores it in the context.
func TestRequestIDGenerated(t *testing.T) {
	var ctxID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxID, _ = utils.RequestIDFromContext(r.Context())
	})

	req := httptest.NewRequest("GET", "/example.com", nil)
	w := httptest.NewRecorder()
	withRequestID(next).ServeHTTP(w, req)

	headerID := w.Header().Get("X-Request-ID")
	if len(headerID) != 16 {
		t.Fatalf("expected generated 16-char request ID, got %q", headerID)
	}
	if ctxID != headerID {
		t.Errorf("context ID %q does not match header ID %q", ctxID, headerID)
	}
}

// TestRequestIDEchoed verifies a valid inbound X-Request-ID is reused as-is.
func TestRequestIDEchoed(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	req := httptest.NewRequest("GET", "/example.com", nil)
	req.Header.Set("X-Request-ID", "client-id_123.abc")
	w := httptest.NewRecorder()
	withRequestID(next).ServeHTTP(w, req)

	if got := w.Header().Get("X-Request-ID"); got != "client-id_123.abc" {
		t.Errorf("expected inbound ID to be echoed, got %q", got)
	}
}

// TestRequestIDInvalidReplaced verifies an inbound ID with unsafe characters
// is discarded and replaced with a generated one.
func TestRequestIDInvalidReplaced(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	for _, bad := range []string{"has space", "newline\ninjected", strings.Repeat("a", 65)} {
		req := httptest.NewRequest("GET", "/example.com", nil)
		req.Header.Set("X-Request-ID", bad)
		w := httptest.NewRecorder()
		withRequestID(next).ServeHTTP(w, req)

		got := w.Header().Get("X-Request-ID")
		if got == bad || len(got) != 16 {
			t.Errorf("invalid inbound ID %q not replaced, got %q", bad, got)
		}
	}
}

// TestHandlerRawCacheHit verifies ?raw=1 reads the raw: cache namespace and
// serves text/plain, isolated from the parsed result under the normal key.
func TestHandlerRawCacheHit(t *testing.T) {
	domain := "rawcachetest99999.cn"
	rawText := "Domain Name: rawcachetest99999.cn\nRegistrar: Example Registrar\n"
	ctx := context.Background()
	if err := config.CacheManager.Set(ctx, "whois:raw:"+domain, rawText, time.Minute); err != nil {
		t.Fatalf("failed to seed raw cache: %v", err)
	}
	// Seed a parsed result under the normal key to prove the raw path does
	// not read it.
	if err := config.CacheManager.Set(ctx, "whois:"+domain, `{"domainName":"parsed"}`, time.Minute); err != nil {
		t.Fatalf("failed to seed parsed cache: %v", err)
	}

	req := httptest.NewRequest("GET", "/"+domain+"?raw=1", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("expected text/plain content type, got %q", ct)
	}
	if !strings.Contains(w.Body.String(), "Example Registrar") {
		t.Errorf("response body missing raw content: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "parsed") {
		t.Errorf("raw request served the parsed cache entry: %s", w.Body.String())
	}
}

// TestHandlerRawIPRejected verifies ?raw is rejected for non-domain queries.
func TestHandlerRawIPRejected(t *testing.T) {
	for _, path := range []string{"/192.0.2.5?raw=1", "/as13335?raw=1"} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		handler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d", path, w.Code)
		}
	}
}

// TestHandlerRawUnknownTLD verifies the raw path returns 404 when the TLD has
// no WHOIS server, without falling through to RDAP.
func TestHandlerRawUnknownTLD(t *testing.T) {
	req := httptest.NewRequest("GET", "/example.zzqqxxnotld?raw=1", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "No WHOIS server known") {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}
