package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/metrics"
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
// flight identity to hang per-query state (the upstream permit, refresh
// ownership, abandonment) on.
type flight struct {
	done    chan struct{} // closed when the flight completes or is abandoned
	outcome queryOutcome  // written before done is closed
	err     error         // written before done is closed

	// abandon is closed when the last waiter leaves before the flight got an
	// upstream permit: nobody wants the result any more, so the flight stops
	// queuing instead of occupying a permit later on nobody's behalf.
	abandon chan struct{}

	// The fields below are guarded by flightsMu.
	waiters    int  // callers currently waiting on done
	finished   bool // set just before done is closed
	permitted  bool // holds an upstream permit; can no longer be abandoned
	abandoned  bool // abandon has been closed
	superseded bool // an overlapping refresh flight owns the cache entry
}

var (
	flightsMu sync.Mutex
	flights   = make(map[string]*flight)
)

// refreshFlightPrefix separates the flights of ?refresh queries from those of
// regular ones. A refresh query asked for a forced upstream fetch, so joining
// a regular flight already in progress would hand it a result it did not
// force while the response still claimed X-Cache: REFRESH. Refresh queries
// still share one flight with each other, and both kinds write the same cache
// key. The NUL byte cannot occur in a cache key built from a validated
// resource name, so the two namespaces cannot collide.
const refreshFlightPrefix = "refresh\x00"

// dedupedQuery runs fn once per key across concurrent callers. Each waiter
// honors its own context and stops waiting when that context ends.
//
// Upstream accounting: a flight takes one server.upstreamLimit permit before
// calling fn and holds it until fn returns, however many callers share it and
// whether they came in singly, from a batch or over MCP — so the limit bounds
// real upstream work, which the request-level concurrency limit cannot (one
// batch request fans out into several flights). Until it has a permit the
// flight is tied to its waiters: if they all leave first, it is abandoned and
// removed from the registry without ever querying. Once it holds a permit it
// is detached: it gets its own timeout, independent of the first caller's
// context, and runs to completion even if every waiter leaves, still
// populating the cache for later requests. Stable not-found/denied errors are
// negative-cached once per flight.
//
// Each flight also holds an entry in the shutdown wait group for its whole
// lifetime, so draining on shutdown waits for detached flights (and their
// cache writes), not just for their former callers.
func dedupedQuery(ctx context.Context, key string, refresh bool, fn func(context.Context) (queryOutcome, error)) (queryOutcome, error) {
	fkey := key
	if refresh {
		fkey = refreshFlightPrefix + key
	}

	flightsMu.Lock()
	f, ok := flights[fkey]
	if !ok {
		f = &flight{done: make(chan struct{}), abandon: make(chan struct{})}
		// A refresh flight owns the cache entry for as long as it runs: a
		// regular flight overlapping it skips its own write, whichever of the
		// two started first. Otherwise the regular query — issued seconds
		// earlier, and possibly answering not-found — could land on top of the
		// forced result and survive there for a whole TTL.
		if refresh {
			if regular, running := flights[key]; running {
				regular.superseded = true
			}
		} else if _, refreshing := flights[refreshFlightPrefix+key]; refreshing {
			f.superseded = true
		}
		flights[fkey] = f
		// The caller's own wait-group entry is still held here (handlers Add
		// before querying), so the counter cannot be observed at zero by a
		// concurrent Wait; adding the flight's entry does not race the drain.
		config.Wg.Add(1)
		go f.run(ctx, key, fkey, fn)
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
		queued := !f.permitted && !f.finished
		if queued && f.waiters == 0 && !f.abandoned {
			// Unregister it in the same critical section, so a caller arriving
			// right after starts a fresh flight instead of joining one that is
			// about to give up.
			f.abandoned = true
			close(f.abandon)
			if flights[fkey] == f {
				delete(flights, fkey)
			}
		}
		flightsMu.Unlock()
		if queued && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			// The whole wait went to queuing for a permit: report the busy
			// upstream budget rather than a generic upstream failure.
			return queryOutcome{}, fmt.Errorf("%w: %w", utils.ErrUpstreamBusy, ctx.Err())
		}
		return queryOutcome{}, ctx.Err()
	}
}

// acquirePermit takes an upstream permit for f, or reports false if f was
// abandoned first. (UpstreamLimiter is nil only in tests that bypass
// config.Load, which run unlimited.)
func (f *flight) acquirePermit() bool {
	limiter := config.UpstreamLimiter
	if limiter != nil {
		select {
		case limiter <- struct{}{}:
		case <-f.abandon:
			return false
		}
	}
	flightsMu.Lock()
	defer flightsMu.Unlock()
	if f.abandoned {
		// Both select cases were ready and the send won; give the permit back.
		if limiter != nil {
			<-limiter
		}
		return false
	}
	f.permitted = true
	return true
}

// run waits for an upstream permit, executes the flight, records its result
// in the cache and publishes it to the waiters. ctx is the first caller's
// context: canceled callers must not cancel the shared query, but its values
// (request ID) are kept for upstream logging via WithoutCancel. cacheKey is
// the entry this flight writes — the result, or a short-TTL negative marker
// for a stable not-found/denied error; fkey is this flight's registry key,
// which differs for refresh queries.
func (f *flight) run(ctx context.Context, cacheKey, fkey string, fn func(context.Context) (queryOutcome, error)) {
	defer config.Wg.Done()

	if !f.acquirePermit() {
		// Abandoned: every waiter is gone and the flight is already out of the
		// registry, so there is nobody to answer and nothing to cache.
		f.publish(fkey, queryOutcome{}, context.Canceled)
		return
	}
	limiter := config.UpstreamLimiter
	metrics.UpstreamInFlight.Inc()
	defer func() {
		metrics.UpstreamInFlight.Dec()
		if limiter != nil {
			<-limiter
		}
	}()

	// The timeout starts once the permit is held: time spent queuing was
	// bounded by the waiters' own deadlines, not charged to the query.
	qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), config.RequestTimeout)
	defer cancel()

	outcome, err := fn(qctx)

	flightsMu.Lock()
	superseded := f.superseded
	flightsMu.Unlock()

	// Write before publishing the result, so a caller that has seen the
	// response can rely on the cache being populated.
	switch {
	case superseded:
	case err != nil:
		utils.CacheNegativeResult(qctx, config.CacheManager, cacheKey, err, config.NegativeCacheExpiration)
	default:
		if err := utils.SetToCache(qctx, config.CacheManager, cacheKey, outcome.body, config.CacheExpiration); err != nil {
			slog.WarnContext(qctx, "cache write error", "key", cacheKey, "err", err)
		}
	}

	f.publish(fkey, outcome, err)
}

// publish unregisters f and hands its result to the waiters. The registry
// entry is only removed if it is still f: an abandoned flight was already
// replaced there by a newer one for the same key.
func (f *flight) publish(fkey string, outcome queryOutcome, err error) {
	flightsMu.Lock()
	if flights[fkey] == f {
		delete(flights, fkey)
	}
	f.outcome, f.err = outcome, err
	f.finished = true
	flightsMu.Unlock()
	close(f.done)
}
