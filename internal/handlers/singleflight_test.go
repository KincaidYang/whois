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
	oldCache, oldLimiter := config.CacheManager, config.ConcurrencyLimiter
	config.CacheManager = utils.NewMemoryCache(10, time.Minute)
	config.ConcurrencyLimiter = make(chan struct{}, 4)
	t.Cleanup(func() { config.CacheManager, config.ConcurrencyLimiter = oldCache, oldLimiter })

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

	// While the flight is detached, the canceled waiter's accounting
	// goroutine must hold one concurrency slot on its behalf, so the
	// configured limit stays a true cap on concurrent upstream work.
	waitFor(t, "detached flight to be counted against the limiter", func() bool {
		return len(config.ConcurrencyLimiter) == 1
	})

	close(release)
	select {
	case out := <-outCh:
		if out.body != "shared" {
			t.Errorf("surviving waiter got body %q, want the shared flight result", out.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("surviving waiter never received the flight result")
	}

	// The flight is done; its slot must be released again.
	waitFor(t, "the flight's limiter slot to be released", func() bool {
		return len(config.ConcurrencyLimiter) == 0
	})

	if n := flights.Load(); n != 1 {
		t.Errorf("flight ran %d times, want 1 (waiters must share one flight)", n)
	}
}

// waitFor polls cond until it holds, failing the test after two seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
