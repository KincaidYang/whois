package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/utils"
)

// TestDedupedQueryWaiterCancel verifies that a waiter whose context ends
// stops waiting immediately, while the flight itself keeps running and
// delivers its result to the remaining waiters, holding exactly one upstream
// permit throughout however many waiters it has.
func TestDedupedQueryWaiterCancel(t *testing.T) {
	setupFlightTest(t)

	synctest.Test(t, func(t *testing.T) {
		config.UpstreamLimiter = make(chan struct{}, 4)
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
		// Wait blocks until every other bubbled goroutine is durably blocked,
		// which is exactly "the second waiter has joined the flight".
		synctest.Wait()
		if n := len(config.UpstreamLimiter); n != 1 {
			t.Fatalf("flight with two waiters holds %d permits, want 1", n)
		}

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

		synctest.Wait()
		if n := len(config.UpstreamLimiter); n != 0 {
			t.Fatalf("finished flight left %d permits held, want 0", n)
		}
		if n := flights.Load(); n != 1 {
			t.Errorf("flight ran %d times, want 1 (waiters must share one flight)", n)
		}
	})
}

// TestDedupedQueryDetachedFlightHoldsOnePermit verifies a flight whose
// waiters all cancel after it started keeps running on exactly one permit —
// its own, taken before querying — and returns it when done. Before permits
// were per flight, a canceled waiter's slot was handed over asynchronously,
// leaving a window in which the running query was not counted at all.
func TestDedupedQueryDetachedFlightHoldsOnePermit(t *testing.T) {
	setupFlightTest(t)

	synctest.Test(t, func(t *testing.T) {
		config.UpstreamLimiter = make(chan struct{}, 4)
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
		for range waiters {
			go func() {
				_, err := dedupedQuery(ctx, key, false, fn)
				errs <- err
			}()
		}
		<-started
		synctest.Wait()

		cancel()
		for range waiters {
			if err := <-errs; !errors.Is(err, context.Canceled) {
				t.Errorf("canceled waiter error = %v, want context.Canceled", err)
			}
		}

		synctest.Wait()
		if n := len(config.UpstreamLimiter); n != 1 {
			t.Fatalf("detached flight holds %d permits, want exactly 1", n)
		}

		close(release)
		synctest.Wait()
		if n := len(config.UpstreamLimiter); n != 0 {
			t.Fatalf("finished flight left %d permits held, want 0", n)
		}
	})
}

// TestDedupedQueryUpstreamLimit verifies server.upstreamLimit bounds the
// number of flights querying upstream at once: distinct keys beyond the limit
// queue for a permit instead of running, and all complete once permits free
// up. This is what bounds batch fan-out, which dispatches one flight per item.
func TestDedupedQueryUpstreamLimit(t *testing.T) {
	setupFlightTest(t)

	synctest.Test(t, func(t *testing.T) {
		const limit, queries = 2, 6
		config.UpstreamLimiter = make(chan struct{}, limit)

		var running, peak atomic.Int32
		release := make(chan struct{})
		fn := func(context.Context) (queryOutcome, error) {
			n := running.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			<-release
			running.Add(-1)
			return queryOutcome{body: "ok"}, nil
		}

		done := make(chan error, queries)
		for i := range queries {
			go func() {
				_, err := dedupedQuery(context.Background(), fmt.Sprintf("whois:sflimit%d", i), false, fn)
				done <- err
			}()
		}

		synctest.Wait()
		if n := running.Load(); n != limit {
			t.Fatalf("%d flights querying upstream, want exactly the limit (%d)", n, limit)
		}

		close(release)
		for range queries {
			if err := <-done; err != nil {
				t.Errorf("query failed: %v", err)
			}
		}
		if p := peak.Load(); p > limit {
			t.Errorf("peak concurrent upstream queries = %d, want at most %d", p, limit)
		}
	})
}

// TestDedupedQueryAbandonsQueuedFlight verifies a flight still queuing for a
// permit when its last waiter leaves never queries upstream, and leaves the
// registry at once so the next caller for that key starts a fresh flight
// instead of joining one that is giving up.
func TestDedupedQueryAbandonsQueuedFlight(t *testing.T) {
	setupFlightTest(t)

	synctest.Test(t, func(t *testing.T) {
		config.UpstreamLimiter = make(chan struct{}, 1)

		// Occupy the only permit.
		releaseBlocker := make(chan struct{})
		blockerDone := make(chan struct{})
		go func() {
			defer close(blockerDone)
			_, _ = dedupedQuery(context.Background(), "whois:sfblocker", false, func(context.Context) (queryOutcome, error) {
				<-releaseBlocker
				return queryOutcome{body: "blocker"}, nil
			})
		}()
		synctest.Wait()

		const key = "whois:sfabandon"
		var queuedRuns atomic.Int32
		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() {
			_, err := dedupedQuery(ctx, key, false, func(context.Context) (queryOutcome, error) {
				queuedRuns.Add(1)
				return queryOutcome{body: "late"}, nil
			})
			errCh <- err
		}()
		synctest.Wait()

		cancel()
		if err := <-errCh; !errors.Is(err, context.Canceled) {
			t.Errorf("waiter error = %v, want context.Canceled", err)
		}
		synctest.Wait()
		flightsMu.Lock()
		_, registered := flights[key]
		flightsMu.Unlock()
		if registered {
			t.Error("abandoned flight is still registered")
		}

		// A new caller gets a fresh flight, which runs once the permit frees.
		freshDone := make(chan queryOutcome, 1)
		go func() {
			out, _ := dedupedQuery(context.Background(), key, false, func(context.Context) (queryOutcome, error) {
				return queryOutcome{body: "fresh"}, nil
			})
			freshDone <- out
		}()
		close(releaseBlocker)
		<-blockerDone
		if out := <-freshDone; out.body != "fresh" {
			t.Errorf("new caller got %q, want its own fresh flight's result", out.body)
		}
		synctest.Wait()
		if n := queuedRuns.Load(); n != 0 {
			t.Errorf("abandoned flight queried upstream %d times, want 0", n)
		}
		if n := len(config.UpstreamLimiter); n != 0 {
			t.Errorf("%d permits still held after everything finished, want 0", n)
		}
	})
}

// TestDedupedQueryQueueDeadlineIsUpstreamBusy verifies a request whose
// deadline passes while its flight is still queuing for a permit is told the
// upstream budget is full (429), not that the upstream query failed (500).
func TestDedupedQueryQueueDeadlineIsUpstreamBusy(t *testing.T) {
	setupFlightTest(t)

	synctest.Test(t, func(t *testing.T) {
		config.UpstreamLimiter = make(chan struct{}, 1)
		releaseBlocker := make(chan struct{})
		blockerDone := make(chan struct{})
		go func() {
			defer close(blockerDone)
			_, _ = dedupedQuery(context.Background(), "whois:sfbusyblocker", false, func(context.Context) (queryOutcome, error) {
				<-releaseBlocker
				return queryOutcome{}, nil
			})
		}()
		synctest.Wait()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := dedupedQuery(ctx, "whois:sfbusy", false, func(context.Context) (queryOutcome, error) {
			return queryOutcome{}, nil
		})
		if !errors.Is(err, utils.ErrUpstreamBusy) {
			t.Errorf("error = %v, want ErrUpstreamBusy", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("error = %v, want it to still wrap context.DeadlineExceeded", err)
		}

		rc := NewResponseCapture()
		utils.HandleQueryError(ctx, rc, err)
		if rc.StatusCode() != http.StatusTooManyRequests {
			t.Errorf("status = %d, want 429", rc.StatusCode())
		}

		close(releaseBlocker)
		<-blockerDone
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

// TestAcquirePermitReturnsPermitWhenAbandoned covers the race in which a
// flight's last waiter abandons it while a permit is also free: select may
// pick either ready case, and when the send wins the permit must be handed
// back rather than kept by a flight that will never query. Repeating makes
// both outcomes all but certain to occur (each run is a fair coin).
func TestAcquirePermitReturnsPermitWhenAbandoned(t *testing.T) {
	limiter := make(chan struct{}, 1)
	for range 100 {
		f := &flight{done: make(chan struct{}), abandon: make(chan struct{}), abandoned: true}
		close(f.abandon)
		if err := f.acquirePermit(context.Background(), limiter); !errors.Is(err, context.Canceled) {
			t.Fatalf("abandoned flight: err = %v, want context.Canceled", err)
		}
		if n := len(limiter); n != 0 {
			t.Fatalf("abandoned flight kept %d permits, want 0", n)
		}
	}
}

// TestAcquirePermitReturnsPermitWhenExpired covers the same race against the
// flight's own timeout: an expired flight that wins the send must not query
// with a dead context (a wasted upstream attempt reported as a generic 500),
// but hand the permit back and report the busy upstream budget.
func TestAcquirePermitReturnsPermitWhenExpired(t *testing.T) {
	limiter := make(chan struct{}, 1)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	for range 100 {
		f := &flight{done: make(chan struct{}), abandon: make(chan struct{})}
		if err := f.acquirePermit(ctx, limiter); !errors.Is(err, utils.ErrUpstreamBusy) {
			t.Fatalf("expired flight: err = %v, want ErrUpstreamBusy", err)
		}
		if n := len(limiter); n != 0 {
			t.Fatalf("expired flight kept %d permits, want 0", n)
		}
		if f.permitted {
			t.Fatal("expired flight was marked permitted")
		}
	}
}

// TestAbandonedRefreshDoesNotSupersedeRegular verifies a refresh that is
// abandoned while still queuing for a permit leaves an overlapping regular
// flight's cache write alone: it never queried, so there is no forced result
// for the regular one to defer to.
func TestAbandonedRefreshDoesNotSupersedeRegular(t *testing.T) {
	setupFlightTest(t)

	synctest.Test(t, func(t *testing.T) {
		config.UpstreamLimiter = make(chan struct{}, 1)
		const key = "whois:sfabandonedrefresh"

		// The regular flight takes the only permit and blocks.
		releaseRegular := make(chan struct{})
		regularDone := make(chan struct{})
		go func() {
			defer close(regularDone)
			_, _ = dedupedQuery(context.Background(), key, false, func(context.Context) (queryOutcome, error) {
				<-releaseRegular
				return queryOutcome{body: "regular"}, nil
			})
		}()
		synctest.Wait()

		// A refresh for the same key queues behind it, then its caller leaves.
		ctx, cancel := context.WithCancel(context.Background())
		refreshErr := make(chan error, 1)
		go func() {
			_, err := dedupedQuery(ctx, key, true, func(context.Context) (queryOutcome, error) {
				return queryOutcome{body: "refreshed"}, nil
			})
			refreshErr <- err
		}()
		synctest.Wait()
		cancel()
		if err := <-refreshErr; !errors.Is(err, context.Canceled) {
			t.Fatalf("refresh waiter error = %v, want context.Canceled", err)
		}

		close(releaseRegular)
		<-regularDone
		got, err := config.CacheManager.Get(context.Background(), key)
		if err != nil || !got.Found || got.Data != "regular" {
			t.Errorf("cache = %+v, %v; want the regular flight's result written", got, err)
		}
	})
}

// TestDedupedQueryFlightTimeoutCoversQueueing verifies a flight's timeout
// counts from its creation: one that queues for a permit past RequestTimeout
// gives up with ErrUpstreamBusy instead of starting a fresh timeout for the
// query, which would let it outlive the shutdown drain.
func TestDedupedQueryFlightTimeoutCoversQueueing(t *testing.T) {
	setupFlightTest(t)

	synctest.Test(t, func(t *testing.T) {
		config.UpstreamLimiter = make(chan struct{}, 1)
		releaseBlocker := make(chan struct{})
		blockerDone := make(chan struct{})
		go func() {
			defer close(blockerDone)
			_, _ = dedupedQuery(context.Background(), "whois:sfqueueblocker", false, func(context.Context) (queryOutcome, error) {
				<-releaseBlocker
				return queryOutcome{}, nil
			})
		}()
		synctest.Wait()

		// The waiter itself never gives up, so only the flight's own timeout
		// can end the queuing.
		var ran atomic.Bool
		_, err := dedupedQuery(context.Background(), "whois:sfqueued", false, func(context.Context) (queryOutcome, error) {
			ran.Store(true)
			return queryOutcome{}, nil
		})
		if !errors.Is(err, utils.ErrUpstreamBusy) {
			t.Errorf("error = %v, want ErrUpstreamBusy once the flight's timeout passed in the queue", err)
		}
		if ran.Load() {
			t.Error("a flight that timed out in the queue must not query upstream")
		}

		close(releaseBlocker)
		<-blockerDone
	})
}

// setupFlightTest gives a flight test its own cache and upstream limiter
// without running config.Load. The cleanup waits for the flight registry to
// drain first: a detached flight still writes the cache after its callers are
// gone, and restoring config.CacheManager under it would be a data race.
func setupFlightTest(t *testing.T) {
	t.Helper()
	oldCache, oldLimiter, oldTTL := config.CacheManager, config.UpstreamLimiter, config.CacheExpiration
	config.CacheManager = utils.NewMemoryCache(10, time.Minute, 0)
	config.UpstreamLimiter = make(chan struct{}, 4)
	config.CacheExpiration = time.Minute
	t.Cleanup(func() {
		waitFor(t, "the flight registry to drain", func() bool {
			flightsMu.Lock()
			defer flightsMu.Unlock()
			return len(flights) == 0
		})
		config.CacheManager, config.UpstreamLimiter, config.CacheExpiration = oldCache, oldLimiter, oldTTL
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
