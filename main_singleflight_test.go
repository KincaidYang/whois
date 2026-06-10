package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KincaidYang/whois/server_lists"
)

// TestHandlerSingleflight verifies that concurrent cache misses for the same
// domain are deduplicated into a single upstream RDAP request, and that all
// waiters receive the shared result.
func TestHandlerSingleflight(t *testing.T) {
	var upstreamCalls int32
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamCalls, 1)
		// Hold the flight open long enough for all concurrent requests to join it.
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/rdap+json")
		fmt.Fprint(w, `{"ldhName":"sftest.zzsfonly"}`)
	}))
	defer fake.Close()

	// Inject a fake RDAP server for a TLD that exists nowhere else, so the
	// query is guaranteed to be a cache miss routed to the fake upstream.
	server_lists.UpdateFromIANA(map[string]string{"zzsfonly": fake.URL + "/"})

	const concurrent = 5
	codes := make([]int, concurrent)
	var wg sync.WaitGroup
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest("GET", "/sftest.zzsfonly", nil)
			w := httptest.NewRecorder()
			handler(w, req)
			codes[i] = w.Code
		}(i)
	}
	wg.Wait()

	for i, code := range codes {
		if code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i, code)
		}
	}
	if calls := atomic.LoadInt32(&upstreamCalls); calls != 1 {
		t.Errorf("expected 1 upstream call, got %d", calls)
	}
}
