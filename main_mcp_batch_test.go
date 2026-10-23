package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/KincaidYang/whois/internal/config"
)

// mcpBatch builds a JSON-RPC batch of n whois_lookup calls. The queries are
// invalid on purpose so the calls answer without any network access.
func mcpBatch(n int) string {
	msgs := make([]string, n)
	for i := range msgs {
		msgs[i] = `{"jsonrpc":"2.0","id":` + strconv.Itoa(i+1) +
			`,"method":"tools/call","params":{"name":"whois_lookup","arguments":{"query":"!!bad` + strconv.Itoa(i) + `"}}}`
	}
	return "[" + strings.Join(msgs, ",") + "]"
}

// mcpRequest posts body to /mcp with the given API key and no
// MCP-Protocol-Version header, which the go-sdk treats as 2025-03-26 — the
// last protocol version that allows JSON-RPC batches.
func mcpRequest(key, body string) *httptest.ResponseRecorder {
	return mcpRequestVersion(key, body, "")
}

// mcpRequestVersion is mcpRequest with an explicit MCP-Protocol-Version.
func mcpRequestVersion(key, body, version string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	if version != "" {
		req.Header.Set("MCP-Protocol-Version", version)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("X-API-Key", key)
	return authRequest(req)
}

func infoAllowed(t *testing.T, key string) bool {
	t.Helper()
	req := httptest.NewRequest("GET", "/info", nil)
	req.Header.Set("X-API-Key", key)
	return authRequest(req).Code == http.StatusOK
}

// TestDebugVarsNotServed verifies the server does not expose the expvar
// endpoint that client_golang's import of expvar registers on
// http.DefaultServeMux.
func TestDebugVarsNotServed(t *testing.T) {
	w := authRequest(httptest.NewRequest("GET", "/debug/vars", nil))
	if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "memstats") {
		t.Fatalf("/debug/vars is served: %d %s", w.Code, w.Body.String())
	}
}

// TestMCPBatchChargesPerToolCall verifies a JSON-RPC batch costs one token per
// tools/call, so it cannot run more lookups than the key's budget allows.
func TestMCPBatchChargesPerToolCall(t *testing.T) {
	withTestAuthClients(t, []config.AuthClient{limitedClient("mcp-key", "mcp", 3)})

	w := mcpRequest("mcp-key", mcpBatch(3))
	if w.Code != http.StatusOK {
		t.Fatalf("batch within budget: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if n := strings.Count(w.Body.String(), `"jsonrpc"`); n != 3 {
		t.Fatalf("expected 3 batch responses, got %d: %s", n, w.Body.String())
	}
	if infoAllowed(t, "mcp-key") {
		t.Error("after a 3-call batch on a 3/min key: expected 429, got through")
	}
}

// TestMCPBatchOverBudget verifies a batch larger than the key's whole budget
// is rejected without running and without spending the rest of the budget.
func TestMCPBatchOverBudget(t *testing.T) {
	withTestAuthClients(t, []config.AuthClient{limitedClient("mcp-key", "mcp", 2)})

	w := mcpRequest("mcp-key", mcpBatch(5))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over-budget batch: expected 429, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Reduce the batch size") {
		t.Errorf("expected the batch-size detail, got: %s", w.Body.String())
	}
	// The request itself cost one token; the second is still there.
	if !infoAllowed(t, "mcp-key") {
		t.Error("over-budget batch spent more than the request's own token")
	}
}

// TestMCPBatchExhaustedBudget verifies a batch that fits the budget but not
// the tokens left answers 429 with Retry-After.
func TestMCPBatchExhaustedBudget(t *testing.T) {
	withTestAuthClients(t, []config.AuthClient{limitedClient("mcp-key", "mcp", 3)})

	if !infoAllowed(t, "mcp-key") {
		t.Fatal("first request rejected")
	}
	w := mcpRequest("mcp-key", mcpBatch(3))
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("expected 429 with Retry-After, got %d (Retry-After %q): %s", w.Code, w.Header().Get("Retry-After"), w.Body.String())
	}
}

// TestMCPBatchNonCallsFree verifies only tools/call messages count: a batch
// of listings costs the one token of its HTTP request.
func TestMCPBatchNonCallsFree(t *testing.T) {
	withTestAuthClients(t, []config.AuthClient{limitedClient("mcp-key", "mcp", 2)})

	body := `[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/list"},{"jsonrpc":"2.0","id":3,"method":"tools/list"}]`
	if w := mcpRequest("mcp-key", body); w.Code != http.StatusOK {
		t.Fatalf("listing batch: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !infoAllowed(t, "mcp-key") {
		t.Error("a batch without tool calls spent more than one token")
	}
}

// TestMCPOversizedBodyWithLimitedKey verifies the body cap still answers 413
// when chargeMCPBatch reads the body first.
func TestMCPOversizedBodyWithLimitedKey(t *testing.T) {
	withTestAuthClients(t, []config.AuthClient{limitedClient("mcp-key", "mcp", 5)})

	w := mcpRequest("mcp-key", "["+strings.Repeat(" ", maxMCPBody)+"]")
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", w.Code, w.Body.String())
	}
}

// TestMCPBatchChargeFollowsProtocolVersion verifies batches are charged only
// when the SDK will run them: on 2025-03-26 (as with no header), but not on a
// version that forbids batching or one the SDK does not support, which it
// rejects whole.
func TestMCPBatchChargeFollowsProtocolVersion(t *testing.T) {
	cases := []struct {
		version  string
		wantCode int
		charged  bool
	}{
		{"2025-03-26", http.StatusOK, true},
		{"2025-06-18", http.StatusBadRequest, false},
		{"2026-07-28", http.StatusBadRequest, false},
		{"2024-01-01", http.StatusBadRequest, false},
	}
	for _, c := range cases {
		t.Run(c.version, func(t *testing.T) {
			withTestAuthClients(t, []config.AuthClient{limitedClient("mcp-key", "mcp", 3)})
			if w := mcpRequestVersion("mcp-key", mcpBatch(3), c.version); w.Code != c.wantCode {
				t.Fatalf("expected %d, got %d: %s", c.wantCode, w.Code, w.Body.String())
			}
			// Charged: 3 tokens gone. Not charged: only the request's own.
			if got := infoAllowed(t, "mcp-key"); got == c.charged {
				t.Errorf("charged = %v, want %v", !got, c.charged)
			}
		})
	}
}

// TestMCPBatchRejectedBySDKNotCharged verifies a legacy-protocol batch the
// SDK rejects whole — here tools/call objects missing the JSON-RPC fields —
// costs only the request's own token.
func TestMCPBatchRejectedBySDKNotCharged(t *testing.T) {
	withTestAuthClients(t, []config.AuthClient{limitedClient("mcp-key", "mcp", 3)})

	body := `[{"method":"tools/call"},{"method":"tools/call"},{"method":"tools/call"}]`
	if w := mcpRequest("mcp-key", body); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed batch: expected 400, got %d: %s", w.Code, w.Body.String())
	}
	for i := range 2 {
		if !infoAllowed(t, "mcp-key") {
			t.Fatalf("follow-up request %d rejected: the rejected batch was charged", i+1)
		}
	}
}

func TestCountBatchToolCalls(t *testing.T) {
	cases := []struct {
		body string
		want int
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`, 0},
		{"  \n\t" + mcpBatch(4), 4},
		{`[{"jsonrpc":"2.0","id":1,"method":"tools/call"},{"jsonrpc":"2.0","id":2,"method":"tools/list"},{"jsonrpc":"2.0","method":"notifications/initialized"}]`, 1},
		// A notification is not a call, even with method tools/call.
		{`[{"jsonrpc":"2.0","method":"tools/call"},{"jsonrpc":"2.0","id":1,"method":"tools/call"}]`, 1},
		// One undecodable message makes the SDK reject the whole batch.
		{`[{"jsonrpc":"2.0","id":1,"method":"tools/call"},{"method":"tools/call"}]`, 0},
		{`[{"jsonrpc":"2.0","id":1,"method":"tools/call"},42]`, 0},
		{`[{"method":"tools/call"},`, 0},
		{`[]`, 0},
		{``, 0},
	}
	for _, c := range cases {
		if got := countBatchToolCalls([]byte(c.body)); got != c.want {
			t.Errorf("countBatchToolCalls(%q) = %d, want %d", c.body, got, c.want)
		}
	}
}

// TestNewServerUsesOwnMux verifies the production server serves the routes
// built by newServerHandler, not http.DefaultServeMux.
func TestNewServerUsesOwnMux(t *testing.T) {
	srv := newServer()
	if srv.Handler == nil || srv.Handler == http.DefaultServeMux {
		t.Fatalf("server handler = %v, want the server's own mux", srv.Handler)
	}
	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/debug/vars", nil))
	if w.Code == http.StatusOK {
		t.Fatalf("/debug/vars is served: %s", w.Body.String())
	}
	if srv.ReadHeaderTimeout == 0 || srv.WriteTimeout == 0 || srv.MaxHeaderBytes == 0 {
		t.Error("server timeouts or header limit not set")
	}
}
