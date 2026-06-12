package mcp

import (
	"context"
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
