package handlers

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/utils"
)

// TestDedupedQueryWaiterCancel verifies that a waiter whose context ends
// stops waiting immediately (releasing its concurrency slot), while the
// flight itself keeps running detached and delivers its result to the
// remaining waiters.
func TestDedupedQueryWaiterCancel(t *testing.T) {
	oldCache := config.CacheManager
	config.CacheManager = utils.NewMemoryCache(10, time.Minute)
	t.Cleanup(func() { config.CacheManager = oldCache })

	var flights atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{})
	fn := func(context.Context) (queryOutcome, error) {
		flights.Add(1)
		close(started)
		<-release
		return queryOutcome{body: "shared", contentType: "application/json"}, nil
	}

	const key = "whois:sfcanceltest"

	// First waiter starts the flight, then gets canceled mid-flight.
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := dedupedQuery(ctx, key, fn)
		errCh <- err
	}()
	<-started

	// Second waiter joins the same in-flight query with a healthy context.
	outCh := make(chan queryOutcome, 1)
	go func() {
		out, _ := dedupedQuery(context.Background(), key, fn)
		outCh <- out
	}()
	time.Sleep(100 * time.Millisecond) // let the second waiter join the flight

	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("canceled waiter error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled waiter did not return until the flight finished")
	}

	close(release)
	select {
	case out := <-outCh:
		if out.body != "shared" {
			t.Errorf("surviving waiter got body %q, want the shared flight result", out.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("surviving waiter never received the flight result")
	}

	if n := flights.Load(); n != 1 {
		t.Errorf("flight ran %d times, want 1 (waiters must share one flight)", n)
	}
}
