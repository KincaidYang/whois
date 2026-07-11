package mcp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/handlers"
	"github.com/KincaidYang/whois/internal/utils"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// setupBatchTest wires up the minimal config state the batch tool needs
// (cache, concurrency limiter, batch flags) without running config.Load.
func setupBatchTest(t *testing.T, enabled bool, maxItems int) {
	t.Helper()
	oldCache, oldLimiter := config.CacheManager, config.ConcurrencyLimiter
	oldEnabled, oldMax := config.BatchEnabled, config.BatchMaxItems
	config.CacheManager = utils.NewMemoryCache(100, time.Minute)
	config.ConcurrencyLimiter = make(chan struct{}, 4)
	config.BatchEnabled, config.BatchMaxItems = enabled, maxItems
	t.Cleanup(func() {
		config.CacheManager, config.ConcurrencyLimiter = oldCache, oldLimiter
		config.BatchEnabled, config.BatchMaxItems = oldEnabled, oldMax
	})
}

func toolText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("tool result has no content")
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("tool result content is %T, want TextContent", result.Content[0])
	}
	return text.Text
}

// TestBatchToolDisabled verifies the tool refuses when batch.enabled is off.
func TestBatchToolDisabled(t *testing.T) {
	setupBatchTest(t, false, 10)

	result, _, err := whoisBatchLookup(context.Background(), nil, &BatchInput{Queries: []string{"example.com"}})
	if err != nil {
		t.Fatalf("tool error: %v", err)
	}
	if !result.IsError || !strings.Contains(toolText(t, result), "disabled") {
		t.Errorf("expected disabled error, got: %+v", result)
	}
}

// TestBatchToolLimits verifies empty and oversized query lists are rejected.
func TestBatchToolLimits(t *testing.T) {
	setupBatchTest(t, true, 2)

	for name, queries := range map[string][]string{
		"empty":    {},
		"too many": {"a.com", "b.com", "c.com"},
	} {
		result, _, err := whoisBatchLookup(context.Background(), nil, &BatchInput{Queries: queries})
		if err != nil {
			t.Fatalf("%s: tool error: %v", name, err)
		}
		if !result.IsError {
			t.Errorf("%s: expected error result", name)
		}
	}
}

// TestBatchToolMixedResults verifies the tool returns per-item results, with
// a cached domain succeeding and an invalid query failing — network-free.
func TestBatchToolMixedResults(t *testing.T) {
	setupBatchTest(t, true, 10)

	domain := "mcpbatchtest.cn"
	if err := config.CacheManager.Set(context.Background(), handlers.CacheKeyPrefix+domain, `{"ldhName":"`+domain+`"}`, time.Minute); err != nil {
		t.Fatalf("failed to seed cache: %v", err)
	}

	result, _, err := whoisBatchLookup(context.Background(), nil, &BatchInput{Queries: []string{domain, "!!invalid!!"}})
	if err != nil {
		t.Fatalf("tool error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success (at least one item succeeded), got error: %s", toolText(t, result))
	}
	payload := toolText(t, result)
	if !strings.Contains(payload, `"status":200`) || !strings.Contains(payload, `"status":400`) {
		t.Errorf("expected mixed 200/400 statuses in payload: %s", payload)
	}
	if !strings.Contains(payload, domain) {
		t.Errorf("payload missing cached domain data: %s", payload)
	}
}

// TestHandlerStatelessJSON drives the streamable HTTP handler end to end and
// verifies its stateless + JSON configuration: a tools/call POST that carries
// no Mcp-Session-Id header (and was never preceded by an initialize request
// on this connection) is answered directly with application/json rather than
// rejected for lacking a session or streamed over SSE.
func TestHandlerStatelessJSON(t *testing.T) {
	setupBatchTest(t, false, 10)

	srv := httptest.NewServer(NewHandler("test"))
	defer srv.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whois_lookup","arguments":{"query":"!!invalid!!"}}}`
	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), "Invalid input") {
		t.Errorf("expected the tool's invalid-input error in the response, got: %s", payload)
	}
}
