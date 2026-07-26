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
	"github.com/KincaidYang/whois/internal/metrics"
	"github.com/KincaidYang/whois/internal/utils"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/time/rate"
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

// TestLookupToolClassifiesIPAndASN verifies the single-lookup tool routes IP,
// CIDR and ASN queries to their handlers on the canonical form of the input,
// the same way the HTTP endpoint does — each one answers from the cache entry
// of that canonical form, network-free.
func TestLookupToolClassifiesIPAndASN(t *testing.T) {
	setupBatchTest(t, false, 10)

	for _, tc := range []struct{ name, cacheKey, query, handle string }{
		{"expanded IPv6", "2001:db8::1", "2001:0DB8:0:0:0:0:0:1", "seeded-ip"},
		{"CIDR with host bits", "198.51.100.0/24", "198.51.100.7/24", "seeded-cidr"},
		{"AS-prefixed number", "64496", "AS64496", "seeded-asn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"objectClassName":"test","handle":"` + tc.handle + `"}`
			if err := config.CacheManager.Set(context.Background(), handlers.CacheKeyPrefix+tc.cacheKey, body, time.Minute); err != nil {
				t.Fatalf("failed to seed cache: %v", err)
			}

			result, _, err := whoisLookup(context.Background(), nil, &WhoisInput{Query: tc.query})
			if err != nil {
				t.Fatalf("tool error: %v", err)
			}
			if result.IsError {
				t.Fatalf("expected success, got error: %s", toolText(t, result))
			}
			if !strings.Contains(toolText(t, result), tc.handle) {
				t.Errorf("expected the cached %s entry, got: %s", tc.handle, toolText(t, result))
			}
		})
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

// TestToolCallsAreMetered verifies MCP tool calls land in the same request
// metrics as HTTP queries, under their own resource types. Without this the
// endpoint the project leads with is invisible in monitoring except through
// the per-key counter, which only exists when authentication is enabled.
func TestToolCallsAreMetered(t *testing.T) {
	setupBatchTest(t, false, 10)

	domain := "mcpmetricstest.cn"
	if err := config.CacheManager.Set(context.Background(), handlers.CacheKeyPrefix+domain, `{"ldhName":"`+domain+`"}`, time.Minute); err != nil {
		t.Fatalf("failed to seed cache: %v", err)
	}

	counter := func(toolType, status string) float64 {
		return testutil.ToFloat64(metrics.HTTPRequestsTotal.WithLabelValues(toolType, status))
	}
	before := map[string]float64{
		"lookup ok":      counter(toolTypeLookup, "200"),
		"lookup bad":     counter(toolTypeLookup, "400"),
		"batch disabled": counter(toolTypeBatch, "403"),
	}

	if _, _, err := whoisLookup(context.Background(), nil, &WhoisInput{Query: domain}); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if _, _, err := whoisLookup(context.Background(), nil, &WhoisInput{Query: "!!invalid!!"}); err != nil {
		t.Fatalf("invalid lookup: %v", err)
	}
	if _, _, err := whoisBatchLookup(context.Background(), nil, &BatchInput{Queries: []string{domain}}); err != nil {
		t.Fatalf("batch: %v", err)
	}

	for name, want := range map[string]struct {
		toolType, status string
	}{
		"lookup ok":      {toolTypeLookup, "200"},
		"lookup bad":     {toolTypeLookup, "400"},
		"batch disabled": {toolTypeBatch, "403"},
	} {
		if got := counter(want.toolType, want.status); got != before[name]+1 {
			t.Errorf("%s: %s{type=%q,status_code=%q} = %v, want %v",
				name, "whois_http_requests_total", want.toolType, want.status, got, before[name]+1)
		}
	}

	// The successful lookup must also be timed; a rejected call must not be.
	if n := testutil.CollectAndCount(metrics.HTTPRequestDuration, "whois_http_request_duration_seconds"); n == 0 {
		t.Error("no latency observations recorded for tool calls")
	}
}

// TestRejectedToolCallsAreMetered verifies calls turned away before any lookup
// are counted too — a saturated concurrency limiter and an exhausted per-key
// budget. These are exactly the conditions an operator needs to see in the
// metrics, and they produce no latency observation because no query ran.
func TestRejectedToolCallsAreMetered(t *testing.T) {
	setupBatchTest(t, true, 10)

	counter := func(toolType, status string) float64 {
		return testutil.ToFloat64(metrics.HTTPRequestsTotal.WithLabelValues(toolType, status))
	}
	lookupBefore := counter(toolTypeLookup, "429")
	batchBefore := counter(toolTypeBatch, "429")

	// Saturate the limiter so both tools are rejected on entry.
	full := make(chan struct{}, 1)
	full <- struct{}{}
	config.ConcurrencyLimiter = full

	result, _, err := whoisLookup(context.Background(), nil, &WhoisInput{Query: "example.com"})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !result.IsError || !strings.Contains(toolText(t, result), "too many concurrent requests") {
		t.Errorf("expected a concurrency rejection, got: %s", toolText(t, result))
	}
	if _, _, err := whoisBatchLookup(context.Background(), nil, &BatchInput{Queries: []string{"example.com"}}); err != nil {
		t.Fatalf("batch: %v", err)
	}

	if got := counter(toolTypeLookup, "429"); got != lookupBefore+1 {
		t.Errorf("lookup 429 count = %v, want %v", got, lookupBefore+1)
	}
	if got := counter(toolTypeBatch, "429"); got != batchBefore+1 {
		t.Errorf("batch 429 count = %v, want %v", got, batchBefore+1)
	}

	// A batch larger than the key's whole budget is rejected as well.
	config.ConcurrencyLimiter = make(chan struct{}, 4)
	client := &config.AuthClient{
		Key:       "tiny",
		Name:      "tiny",
		RateLimit: 2,
		Limiter:   rate.NewLimiter(rate.Limit(2)/60, 2),
	}
	ctx := config.WithAuthClient(context.Background(), client)

	batchBefore = counter(toolTypeBatch, "429")
	result, _, err = whoisBatchLookup(ctx, nil, &BatchInput{Queries: []string{"a.cn", "b.cn", "c.cn", "d.cn"}})
	if err != nil {
		t.Fatalf("over-budget batch: %v", err)
	}
	if !result.IsError || !strings.Contains(toolText(t, result), "reduce the batch size") {
		t.Errorf("expected an over-budget rejection, got: %s", toolText(t, result))
	}
	if got := counter(toolTypeBatch, "429"); got != batchBefore+1 {
		t.Errorf("over-budget 429 count = %v, want %v", got, batchBefore+1)
	}
}
