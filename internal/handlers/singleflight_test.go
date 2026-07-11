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
// stops waiting immediately, while the flight itself keeps running and
// delivers its result to the remaining waiters — and that as long as one
// waiter remains, no extra concurrency slot is transferred to the flight
// (the surviving waiter's handler slot already covers it).
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

	// A waiter is still attached, so the flight must not be charged a slot
	// of its own; in the real server the surviving waiter's handler slot
	// covers it.
	for deadline := time.Now().Add(200 * time.Millisecond); time.Now().Before(deadline); {
		if n := len(config.ConcurrencyLimiter); n != 0 {
			t.Fatalf("flight with a live waiter holds %d slots, want 0", n)
		}
		time.Sleep(10 * time.Millisecond)
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

	// The flight is done; its slot must be released again.
	waitFor(t, "the flight's limiter slot to be released", func() bool {
		return len(config.ConcurrencyLimiter) == 0
	})

	if n := flights.Load(); n != 1 {
		t.Errorf("flight ran %d times, want 1 (waiters must share one flight)", n)
	}
}

// TestDedupedQueryCanceledWaitersShareOneSlot verifies that no matter how
// many waiters cancel while sharing one flight, the detached flight is
// charged exactly one concurrency slot — not one per canceled waiter, which
// would let clients drain the limiter by querying one slow resource and
// disconnecting.
func TestDedupedQueryCanceledWaitersShareOneSlot(t *testing.T) {
	oldCache, oldLimiter := config.CacheManager, config.ConcurrencyLimiter
	config.CacheManager = utils.NewMemoryCache(10, time.Minute)
	config.ConcurrencyLimiter = make(chan struct{}, 4)
	t.Cleanup(func() { config.CacheManager, config.ConcurrencyLimiter = oldCache, oldLimiter })

	release := make(chan struct{})
	started := make(chan struct{})
	fn := func(context.Context) (queryOutcome, error) {
		close(started)
		<-release
		return queryOutcome{body: "shared"}, nil
	}

	const key = "whois:sfmulticancel"
	const waiters = 3

	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			_, err := dedupedQuery(ctx, key, fn)
			errs <- err
		}()
	}
	<-started
	waitFor(t, "all waiters to join the flight", func() bool {
		flightsMu.Lock()
		defer flightsMu.Unlock()
		return flights[key] != nil && flights[key].waiters == waiters
	})

	cancel()
	for i := 0; i < waiters; i++ {
		if err := <-errs; !errors.Is(err, context.Canceled) {
			t.Errorf("canceled waiter error = %v, want context.Canceled", err)
		}
	}

	waitFor(t, "the detached flight to hold one slot", func() bool {
		return len(config.ConcurrencyLimiter) == 1
	})
	// All cancellations are processed; the count must stay at one, not creep
	// toward one slot per canceled waiter.
	for deadline := time.Now().Add(300 * time.Millisecond); time.Now().Before(deadline); {
		if n := len(config.ConcurrencyLimiter); n != 1 {
			t.Fatalf("detached flight holds %d slots, want exactly 1", n)
		}
		time.Sleep(10 * time.Millisecond)
	}

	close(release)
	waitFor(t, "the flight's slot to be released", func() bool {
		return len(config.ConcurrencyLimiter) == 0
	})
}

// TestDedupedQueryShutdownDrainCoversFlight verifies that a flight whose
// waiters have all canceled still holds a shutdown wait-group entry, so the
// drain in main waits for its upstream query and cache writes before the
// cache and Redis clients are closed.
func TestDedupedQueryShutdownDrainCoversFlight(t *testing.T) {
	oldCache, oldLimiter := config.CacheManager, config.ConcurrencyLimiter
	config.CacheManager = utils.NewMemoryCache(10, time.Minute)
	config.ConcurrencyLimiter = make(chan struct{}, 4)
	t.Cleanup(func() { config.CacheManager, config.ConcurrencyLimiter = oldCache, oldLimiter })

	release := make(chan struct{})
	started := make(chan struct{})
	fn := func(context.Context) (queryOutcome, error) {
		close(started)
		<-release
		return queryOutcome{body: "shared"}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := dedupedQuery(ctx, "whois:sfdraintest", fn)
		errCh <- err
	}()
	<-started
	cancel()
	<-errCh // the only waiter is gone; the flight is fully detached

	drained := make(chan struct{})
	go func() {
		config.Wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
		t.Fatal("shutdown drain completed while the detached flight was still running")
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown drain did not complete after the flight finished")
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
