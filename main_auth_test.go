package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/utils"
)

// withTestAuthKeys configures anonymous API keys for the duration of a test.
func withTestAuthKeys(t *testing.T, keys ...string) {
	t.Helper()
	clients := make([]config.AuthClient, len(keys))
	for i, key := range keys {
		clients[i] = config.AuthClient{Key: key, Name: fmt.Sprintf("key%d", i+1)}
	}
	withTestAuthClients(t, clients)
}

// withTestAuthClients configures full auth clients for the duration of a test.
func withTestAuthClients(t *testing.T, clients []config.AuthClient) {
	t.Helper()
	old := config.AuthClients
	config.AuthClients = clients
	t.Cleanup(func() { config.AuthClients = old })
}

// authRequest runs a request through the full production middleware chain.
func authRequest(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	withRequestID(withCORS(withAuth(newTestMux()))).ServeHTTP(w, req)
	return w
}

// TestAuthDisabledAllOpen verifies that with no keys configured (the default)
// every endpoint stays open.
func TestAuthDisabledAllOpen(t *testing.T) {
	withTestAuthKeys(t) // empty

	for _, path := range []string{"/info", "/openapi.json", "/health"} {
		w := authRequest(httptest.NewRequest("GET", path, nil))
		if w.Code != http.StatusOK {
			t.Errorf("%s: expected 200 with auth disabled, got %d", path, w.Code)
		}
	}
}

// TestAuthMissingKey verifies protected endpoints return a 401 problem
// response when auth is enabled and no key is sent.
func TestAuthMissingKey(t *testing.T) {
	withTestAuthKeys(t, "test-key-1")

	for _, path := range []string{"/example.com", "/domain/example.com", "/info", "/metrics", "/openapi.json", "/mcp"} {
		w := authRequest(httptest.NewRequest("GET", path, nil))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: expected 401, got %d", path, w.Code)
			continue
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
			t.Errorf("%s: expected problem+json, got %q", path, ct)
		}
		if got := w.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer") {
			t.Errorf("%s: WWW-Authenticate: got %q", path, got)
		}
		if !strings.Contains(w.Body.String(), "#unauthorized") {
			t.Errorf("%s: body missing unauthorized problem type: %s", path, w.Body.String())
		}
	}
}

// TestAuthBearerKey verifies a configured key sent as Authorization: Bearer
// is accepted, including case-insensitive scheme matching.
func TestAuthBearerKey(t *testing.T) {
	withTestAuthKeys(t, "test-key-1", "test-key-2")

	for _, scheme := range []string{"Bearer", "bearer", "BEARER"} {
		req := httptest.NewRequest("GET", "/info", nil)
		req.Header.Set("Authorization", scheme+" test-key-2")
		if w := authRequest(req); w.Code != http.StatusOK {
			t.Errorf("scheme %q: expected 200, got %d", scheme, w.Code)
		}
	}
}

// TestAuthAPIKeyHeader verifies a configured key sent as X-API-Key is accepted.
func TestAuthAPIKeyHeader(t *testing.T) {
	withTestAuthKeys(t, "test-key-1")

	req := httptest.NewRequest("GET", "/info", nil)
	req.Header.Set("X-API-Key", "test-key-1")
	if w := authRequest(req); w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestAuthInvalidBearerFallsBackToAPIKey verifies a stale bearer token does
// not mask a valid X-API-Key sent on the same request.
func TestAuthInvalidBearerFallsBackToAPIKey(t *testing.T) {
	withTestAuthKeys(t, "test-key-1")

	req := httptest.NewRequest("GET", "/info", nil)
	req.Header.Set("Authorization", "Bearer stale-token")
	req.Header.Set("X-API-Key", "test-key-1")
	if w := authRequest(req); w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestAuthEmptyKeyNeverMatches verifies a request with no credentials is
// rejected even if an empty string somehow ends up in the configured keys.
func TestAuthEmptyKeyNeverMatches(t *testing.T) {
	withTestAuthKeys(t, "")

	w := authRequest(httptest.NewRequest("GET", "/info", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestAuthWrongKey verifies unknown keys are rejected on both headers.
func TestAuthWrongKey(t *testing.T) {
	withTestAuthKeys(t, "test-key-1")

	req := httptest.NewRequest("GET", "/info", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	if w := authRequest(req); w.Code != http.StatusUnauthorized {
		t.Errorf("Bearer wrong key: expected 401, got %d", w.Code)
	}

	req = httptest.NewRequest("GET", "/info", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	if w := authRequest(req); w.Code != http.StatusUnauthorized {
		t.Errorf("X-API-Key wrong key: expected 401, got %d", w.Code)
	}
}

// TestAuthProbesExempt verifies /health and /ready stay open with auth
// enabled, so liveness probes keep working without credentials.
func TestAuthProbesExempt(t *testing.T) {
	withTestAuthKeys(t, "test-key-1")

	w := authRequest(httptest.NewRequest("GET", "/health", nil))
	if w.Code != http.StatusOK {
		t.Errorf("/health: expected 200, got %d", w.Code)
	}

	w = authRequest(httptest.NewRequest("GET", "/ready", nil))
	if w.Code != http.StatusOK && w.Code != http.StatusServiceUnavailable {
		t.Errorf("/ready: expected 200 or 503, got %d", w.Code)
	}
}

// TestAuthClientInContext verifies the matched client's name reaches the
// request context, where logs (and later per-key rate limiting) pick it up.
func TestAuthClientInContext(t *testing.T) {
	withTestAuthClients(t, []config.AuthClient{
		{Key: "test-key-1", Name: "ci"},
		{Key: "test-key-2", Name: "monitor"},
	})

	var gotName string
	var gotOK bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotName, gotOK = utils.ClientFromContext(r.Context())
	})

	req := httptest.NewRequest("GET", "/info", nil)
	req.Header.Set("X-API-Key", "test-key-2")
	withAuth(inner).ServeHTTP(httptest.NewRecorder(), req)

	if !gotOK || gotName != "monitor" {
		t.Errorf("client in context: got %q (ok=%v), want \"monitor\"", gotName, gotOK)
	}
}

// TestAuthPreflightExempt verifies CORS preflight requests are answered
// before authentication, so browsers can complete preflight without a key.
func TestAuthPreflightExempt(t *testing.T) {
	withTestAuthKeys(t, "test-key-1")

	req := httptest.NewRequest("OPTIONS", "/example.com", nil)
	req.Header.Set("Origin", "https://example.org")
	w := authRequest(req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Authorization") || !strings.Contains(got, "X-API-Key") {
		t.Errorf("Access-Control-Allow-Headers missing auth headers: %q", got)
	}
}
