package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/handlers"
)

// withTestBatch enables the batch endpoint for the duration of a test.
func withTestBatch(t *testing.T, enabled bool, maxItems int) {
	t.Helper()
	oldEnabled, oldMax := config.BatchEnabled, config.BatchMaxItems
	config.BatchEnabled, config.BatchMaxItems = enabled, maxItems
	t.Cleanup(func() { config.BatchEnabled, config.BatchMaxItems = oldEnabled, oldMax })
}

func postBatch(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	batchHandler(w, req)
	return w
}

// TestBatchDisabled verifies the endpoint is off by default and answers with
// the batch-disabled problem.
func TestBatchDisabled(t *testing.T) {
	withTestBatch(t, false, 10)

	w := postBatch(t, `{"queries": ["example.com"]}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "#batch-disabled") {
		t.Errorf("body missing batch-disabled problem type: %s", w.Body.String())
	}
}

// TestBatchMethodNotAllowed verifies non-POST requests get a 405 with Allow.
func TestBatchMethodNotAllowed(t *testing.T) {
	withTestBatch(t, true, 10)

	req := httptest.NewRequest("GET", "/batch", nil)
	w := httptest.NewRecorder()
	batchHandler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
	if got := w.Header().Get("Allow"); got != "POST" {
		t.Errorf("Allow: got %q, want POST", got)
	}
}

// TestBatchBadRequests verifies malformed bodies, empty lists and oversized
// batches are rejected with 400.
func TestBatchBadRequests(t *testing.T) {
	withTestBatch(t, true, 2)

	for name, body := range map[string]string{
		"not json":      `not json at all`,
		"unknown field": `{"queris": ["example.com"]}`,
		"empty list":    `{"queries": []}`,
		"over maxItems": `{"queries": ["a.com", "b.com", "c.com"]}`,
	} {
		w := postBatch(t, body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d", name, w.Code)
		}
	}
}

// TestBatchMixedResults verifies per-item successes and failures coexist in
// one 200 response: a cached domain answers from cache, an invalid input gets
// a per-item 400 problem, and an unknown TLD reports its per-item 500 — all
// network-free.
func TestBatchMixedResults(t *testing.T) {
	withTestBatch(t, true, 10)

	domain := "batchcachedtest.cn"
	key := handlers.CacheKeyPrefix + domain
	if err := config.CacheManager.Set(context.Background(), key, `{"ldhName":"`+domain+`"}`, time.Minute); err != nil {
		t.Fatalf("failed to seed cache: %v", err)
	}

	w := postBatch(t, `{"queries": ["`+domain+`", "!!not-valid!!", "nx.zzqqxxnotld"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp handlers.BatchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(resp.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(resp.Results))
	}

	cached := resp.Results[0]
	if cached.Query != domain || cached.Status != http.StatusOK || cached.Error != nil {
		t.Errorf("cached item: %+v", cached)
	}
	if !strings.Contains(string(cached.Data), domain) {
		t.Errorf("cached item data missing domain: %s", cached.Data)
	}

	invalid := resp.Results[1]
	if invalid.Status != http.StatusBadRequest || invalid.Data != nil {
		t.Errorf("invalid item: %+v", invalid)
	}
	if !strings.Contains(string(invalid.Error), "#bad-request") {
		t.Errorf("invalid item error missing problem type: %s", invalid.Error)
	}

	noServer := resp.Results[2]
	if noServer.Status != http.StatusInternalServerError || noServer.Data != nil {
		t.Errorf("no-server item: %+v", noServer)
	}
}

// TestBatchExpiredDeadline verifies queries still queued when the batch
// deadline expires are reported as per-item errors instead of starting late —
// the singleflight layer would otherwise give them a fresh detached timeout
// that can outlive the HTTP response.
func TestBatchExpiredDeadline(t *testing.T) {
	withTestBatch(t, true, 10)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results := handlers.RunBatch(ctx, []string{"a.cn", "b.cn"})
	for _, item := range results {
		if item.Status != http.StatusInternalServerError {
			t.Errorf("%s: expected 500 for expired deadline, got %d", item.Query, item.Status)
		}
		if !strings.Contains(string(item.Error), "deadline expired") {
			t.Errorf("%s: expected deadline detail, got: %s", item.Query, item.Error)
		}
	}
}

// TestBatchChargesRateLimitTokens verifies a batch of N queries consumes N
// tokens of the key's budget: the middleware charges 1, the handler the
// remaining N-1, so the next request is rejected.
func TestBatchChargesRateLimitTokens(t *testing.T) {
	withTestBatch(t, true, 10)
	withTestAuthClients(t, []config.AuthClient{limitedClient("batch-key", "batcher", 3)})

	// Seed all three so the batch itself stays network-free.
	for _, d := range []string{"batchtokena.cn", "batchtokenb.cn", "batchtokenc.cn"} {
		if err := config.CacheManager.Set(context.Background(), handlers.CacheKeyPrefix+d, `{"ldhName":"`+d+`"}`, time.Minute); err != nil {
			t.Fatalf("failed to seed cache: %v", err)
		}
	}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`{"queries": ["batchtokena.cn", "batchtokenb.cn", "batchtokenc.cn"]}`))
	req.Header.Set("X-API-Key", "batch-key")
	w := authRequest(req)
	if w.Code != http.StatusOK {
		t.Fatalf("batch within budget: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Budget (3/min) is now fully spent: a single follow-up request is 429.
	follow := httptest.NewRequest("GET", "/info", nil)
	follow.Header.Set("X-API-Key", "batch-key")
	if w := authRequest(follow); w.Code != http.StatusTooManyRequests {
		t.Errorf("after batch: expected 429, got %d", w.Code)
	}
}

// TestBatchOverBudget verifies a batch larger than the key's whole budget is
// rejected outright (no Retry-After could ever make it succeed).
func TestBatchOverBudget(t *testing.T) {
	withTestBatch(t, true, 10)
	withTestAuthClients(t, []config.AuthClient{limitedClient("tiny-key", "tiny", 2)})

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`{"queries": ["a.cn", "b.cn", "c.cn", "d.cn"]}`))
	req.Header.Set("X-API-Key", "tiny-key")
	w := authRequest(req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Reduce the batch size") {
		t.Errorf("expected the over-budget detail, got: %s", w.Body.String())
	}
}
