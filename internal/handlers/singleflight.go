package handlers

import (
	"context"
	"sync"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/utils"
)

// queryOutcome is the result of an upstream query, shared between concurrent
// requests waiting on the same flight.
type queryOutcome struct {
	body        string
	contentType string
}

// flight is one in-progress upstream query, shared by all concurrent requests
// for the same cache key. It replaces x/sync/singleflight, which offers no
// flight identity: with it, every canceled waiter transferred its own
// concurrency slot to the same shared flight, so one upstream request could
// hold as many slots as it had canceled waiters.
type flight struct {
	done    chan struct{} // closed when the query completes
	outcome queryOutcome  // written before done is closed
	err     error         // written before done is closed

	// The fields below are guarded by flightsMu.
	waiters  int  // callers currently waiting on done
	finished bool // set just before done is closed
	slotHeld bool // a concurrency slot has been transferred to this flight
}

var (
	flightsMu sync.Mutex
	flights   = make(map[string]*flight)
)

// dedupedQuery runs fn once per key across concurrent callers. The flight gets
// its own timeout, detached from the first caller's context, so one client
// disconnecting does not fail the other requests waiting on the same key —
// but each waiter honors its own context and stops waiting when that context
// ends, while the flight runs to completion and still populates the cache for
// later requests. Stable not-found/denied errors are negative-cached once per
// flight.
//
// Concurrency accounting: while a flight has waiters, their handlers' slots
// cover it. When the last waiter cancels, exactly one slot is transferred to
// the detached flight (regardless of how many waiters canceled before it), so
// server.rateLimit stays a cap on concurrent upstream work — otherwise a
// client could disconnect repeatedly to stack detached flights beyond the
// configured limit. Each flight also holds an entry in the shutdown wait
// group for its whole lifetime, so draining on shutdown waits for detached
// flights (and their cache writes), not just for their former callers.
func dedupedQuery(ctx context.Context, key string, fn func(context.Context) (queryOutcome, error)) (queryOutcome, error) {
	flightsMu.Lock()
	f, ok := flights[key]
	if !ok {
		f = &flight{done: make(chan struct{})}
		flights[key] = f
		// The caller's own wait-group entry is still held here (handlers Add
		// before querying), so the counter cannot be observed at zero by a
		// concurrent Wait; adding the flight's entry does not race the drain.
		config.Wg.Add(1)
		go f.run(ctx, key, fn)
	}
	f.waiters++
	flightsMu.Unlock()

	select {
	case <-f.done:
		flightsMu.Lock()
		f.waiters--
		flightsMu.Unlock()
		return f.outcome, f.err
	case <-ctx.Done():
		flightsMu.Lock()
		f.waiters--
		// Transfer one slot to the flight when its last waiter leaves. If a
		// new waiter joins the still-running flight afterwards, the flight
		// briefly counts twice (its slot plus the new caller's); that
		// overcounts the cap, never undercuts it. (Limiter is nil only in
		// tests that bypass config.Load.)
		limiter := config.ConcurrencyLimiter
		transfer := f.waiters == 0 && !f.finished && !f.slotHeld && limiter != nil
		if transfer {
			f.slotHeld = true
		}
		flightsMu.Unlock()
		if transfer {
			go func() {
				limiter <- struct{}{}
				<-f.done
				<-limiter
			}()
		}
		return queryOutcome{}, ctx.Err()
	}
}

// run executes the flight and publishes its result. ctx is the first caller's
// context: canceled callers must not cancel the shared query, but its values
// (request ID) are kept for upstream logging via WithoutCancel.
func (f *flight) run(ctx context.Context, key string, fn func(context.Context) (queryOutcome, error)) {
	defer config.Wg.Done()

	qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), config.RequestTimeout)
	defer cancel()

	outcome, err := fn(qctx)
	if err != nil {
		utils.CacheNegativeResult(qctx, config.CacheManager, key, err, config.NegativeCacheExpiration)
	}

	flightsMu.Lock()
	delete(flights, key)
	f.outcome, f.err = outcome, err
	f.finished = true
	flightsMu.Unlock()
	close(f.done)
}
