package handlers

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestRunBatchDeadlineWhileQueued verifies a query that is still waiting for
// a concurrency slot when the deadline expires reports the deadline instead
// of running. The unbuffered semaphore has no receiver, so the select can
// only pick ctx.Done(): the test covers that case on every run, where the
// already-expired test in the root package reaches it only when the select
// happens to choose it over a free slot.
func TestRunBatchDeadlineWhileQueued(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results := runBatch(ctx, []string{"a.cn", "b.cn"}, make(chan struct{}))
	for _, item := range results {
		if item.Status != http.StatusInternalServerError {
			t.Errorf("%s: expected 500 for expired deadline, got %d", item.Query, item.Status)
		}
		if !strings.Contains(string(item.Error), "deadline expired") {
			t.Errorf("%s: expected deadline detail, got: %s", item.Query, item.Error)
		}
	}
}
