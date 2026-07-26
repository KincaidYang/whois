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
	setupFlightTest(t)

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
		_, err := dedupedQuery(ctx, key, false, fn)
		errCh <- err
	}()
	<-started

	// Second waiter joins the same in-flight query with a healthy context.
	outCh := make(chan queryOutcome, 1)
	go func() {
		out, _ := dedupedQuery(context.Background(), key, false, fn)
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
	setupFlightTest(t)

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
			_, err := dedupedQuery(ctx, key, false, fn)
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
	setupFlightTest(t)

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
		_, err := dedupedQuery(ctx, "whois:sfdraintest", false, fn)
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

// TestDedupedQueryRefreshDoesNotJoinRegularFlight verifies a ?refresh query
// runs its own upstream query instead of attaching to a regular flight
// already in progress for the same cache key: a refresh caller asked for a
// forced fetch, and would otherwise be handed a result it did not force while
// the response still reported X-Cache: REFRESH.
func TestDedupedQueryRefreshDoesNotJoinRegularFlight(t *testing.T) {
	setupFlightTest(t)

	const key = "whois:sfrefreshtest"
	var runs atomic.Int32
	release := make(chan struct{})
	regularStarted := make(chan struct{})

	go func() {
		_, _ = dedupedQuery(context.Background(), key, false, func(context.Context) (queryOutcome, error) {
			runs.Add(1)
			close(regularStarted)
			<-release
			return queryOutcome{body: "regular"}, nil
		})
	}()
	<-regularStarted

	// The refresh query starts while the regular flight is still running.
	out, err := dedupedQuery(context.Background(), key, true, func(context.Context) (queryOutcome, error) {
		runs.Add(1)
		return queryOutcome{body: "refreshed"}, nil
	})
	if err != nil {
		t.Fatalf("refresh query failed: %v", err)
	}
	if out.body != "refreshed" {
		t.Errorf("refresh query body = %q, want %q (it joined the regular flight)", out.body, "refreshed")
	}

	close(release)
	waitFor(t, "both flights to finish", func() bool { return runs.Load() == 2 })

	// Two refresh queries for the same key still share one flight.
	runs.Store(0)
	release2 := make(chan struct{})
	refreshStarted := make(chan struct{})
	fn := func(context.Context) (queryOutcome, error) {
		runs.Add(1)
		close(refreshStarted)
		<-release2
		return queryOutcome{body: "refreshed"}, nil
	}
	go func() { _, _ = dedupedQuery(context.Background(), key, true, fn) }()
	<-refreshStarted
	done := make(chan struct{})
	go func() {
		defer close(done)
		if out, _ := dedupedQuery(context.Background(), key, true, fn); out.body != "refreshed" {
			t.Errorf("second refresh body = %q, want the shared flight result", out.body)
		}
	}()
	waitFor(t, "the second refresh waiter to join", func() bool {
		flightsMu.Lock()
		defer flightsMu.Unlock()
		f := flights[refreshFlightPrefix+key]
		return f != nil && f.waiters == 2
	})
	close(release2)
	<-done
	if n := runs.Load(); n != 1 {
		t.Errorf("refresh flight ran %d times, want 1 (refresh queries must share one flight)", n)
	}
}

// TestRefreshFlightOwnsCacheEntry verifies a regular flight overlapping a
// refresh does not write the cache: whichever of the two finishes last, the
// forced result is what stays cached. Otherwise the regular query — issued
// before the refresh, and possibly answering not-found — would land on top of
// the refreshed entry and be served for a whole TTL.
func TestRefreshFlightOwnsCacheEntry(t *testing.T) {
	setupFlightTest(t)

	cached := func(t *testing.T, key string) string {
		t.Helper()
		got, err := config.CacheManager.Get(context.Background(), key)
		if err != nil {
			t.Fatalf("cache read: %v", err)
		}
		if !got.Found {
			return ""
		}
		return got.Data
	}

	// The regular flight starts first and finishes last, with an error: its
	// negative marker must not replace the refreshed result.
	const key = "whois:sfrefreshowner"
	release := make(chan struct{})
	regularStarted := make(chan struct{})
	regularDone := make(chan error, 1)
	go func() {
		_, err := dedupedQuery(context.Background(), key, false, func(context.Context) (queryOutcome, error) {
			close(regularStarted)
			<-release
			return queryOutcome{}, utils.ErrDomainNotFound
		})
		regularDone <- err
	}()
	<-regularStarted

	if _, err := dedupedQuery(context.Background(), key, true, func(context.Context) (queryOutcome, error) {
		return queryOutcome{body: "refreshed"}, nil
	}); err != nil {
		t.Fatalf("refresh query failed: %v", err)
	}
	if got := cached(t, key); got != "refreshed" {
		t.Fatalf("after refresh, cache holds %q, want %q", got, "refreshed")
	}

	close(release)
	if err := <-regularDone; !errors.Is(err, utils.ErrDomainNotFound) {
		t.Errorf("regular waiter error = %v, want its own flight's error", err)
	}
	if got := cached(t, key); got != "refreshed" {
		t.Errorf("the superseded flight overwrote the refreshed entry with %q", got)
	}

	// The reverse order: a regular flight started while a refresh is running
	// is superseded too, so its result cannot outlive the refresh either.
	const key2 = "whois:sfrefreshowner2"
	release2 := make(chan struct{})
	refreshStarted := make(chan struct{})
	refreshDone := make(chan struct{})
	go func() {
		defer close(refreshDone)
		_, _ = dedupedQuery(context.Background(), key2, true, func(context.Context) (queryOutcome, error) {
			close(refreshStarted)
			<-release2
			return queryOutcome{body: "refreshed"}, nil
		})
	}()
	<-refreshStarted

	if _, err := dedupedQuery(context.Background(), key2, false, func(context.Context) (queryOutcome, error) {
		return queryOutcome{body: "regular"}, nil
	}); err != nil {
		t.Fatalf("regular query failed: %v", err)
	}
	if got := cached(t, key2); got != "" {
		t.Errorf("the superseded regular flight wrote %q while a refresh was in flight", got)
	}

	close(release2)
	<-refreshDone
	if got := cached(t, key2); got != "refreshed" {
		t.Errorf("after the refresh finished, cache holds %q, want %q", got, "refreshed")
	}
}

// setupFlightTest gives a flight test its own cache and concurrency limiter
// without running config.Load. The cleanup waits for the flight registry to
// drain first: a detached flight still writes the cache after its callers are
// gone, and restoring config.CacheManager under it would be a data race.
func setupFlightTest(t *testing.T) {
	t.Helper()
	oldCache, oldLimiter, oldTTL := config.CacheManager, config.ConcurrencyLimiter, config.CacheExpiration
	config.CacheManager = utils.NewMemoryCache(10, time.Minute)
	config.ConcurrencyLimiter = make(chan struct{}, 4)
	config.CacheExpiration = time.Minute
	t.Cleanup(func() {
		waitFor(t, "the flight registry to drain", func() bool {
			flightsMu.Lock()
			defer flightsMu.Unlock()
			return len(flights) == 0
		})
		config.CacheManager, config.ConcurrencyLimiter, config.CacheExpiration = oldCache, oldLimiter, oldTTL
	})
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
