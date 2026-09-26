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

	// cacheKey is the entry this flight writes; refresh marks a ?refresh
	// flight, which takes ownership of that entry once it starts querying.
	cacheKey string
	refresh  bool
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
// is detached and runs to completion even if every waiter leaves, still
// populating the cache for later requests. Its timeout is its own,
// independent of the first caller's context, and counts from the flight's
// creation, so queuing for a permit and querying together never exceed
// RequestTimeout. Stable not-found/denied errors are
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
		f = &flight{done: make(chan struct{}), abandon: make(chan struct{}), cacheKey: key, refresh: refresh}
		// A regular flight started while a refresh is already querying is
		// superseded from the outset (see acquirePermit for the other order).
		if !refresh {
			if r, refreshing := flights[refreshFlightPrefix+key]; refreshing && r.permitted {
				f.superseded = true
			}
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

// acquirePermit takes an upstream permit for f. It gives up and returns an
// error if f is abandoned first (every waiter left) or if ctx — the flight's
// own timeout, which covers queuing as well as the query itself — ends
// before a permit frees up. A nil limiter means unlimited (only tests that
// bypass config.Load run without one).
//
// A refresh flight takes ownership of its cache entry here, once it is
// certain to query: a regular flight overlapping it skips its own write,
// whichever of the two started first. Otherwise the regular query — issued
// seconds earlier, and possibly answering not-found — could land on top of
// the forced result and survive there for a whole TTL. A refresh that never
// gets this far (abandoned, or timed out in the queue) produces no result, so
// it must not suppress the regular one's write.
func (f *flight) acquirePermit(ctx context.Context, limiter chan struct{}) error {
	if limiter != nil {
		select {
		case limiter <- struct{}{}:
		case <-f.abandon:
			return context.Canceled
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", utils.ErrUpstreamBusy, ctx.Err())
		}
	}
	flightsMu.Lock()
	defer flightsMu.Unlock()
	// select picks at random among ready cases, so the send may have won even
	// though the flight was already abandoned or out of time; either way it
	// must not query, and the permit goes back.
	var err error
	switch {
	case f.abandoned:
		err = context.Canceled
	case ctx.Err() != nil:
		err = fmt.Errorf("%w: %w", utils.ErrUpstreamBusy, ctx.Err())
	}
	if err != nil {
		if limiter != nil {
			<-limiter
		}
		return err
	}
	f.permitted = true
	if f.refresh {
		if regular, running := flights[f.cacheKey]; running {
			regular.superseded = true
		}
	}
	return nil
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

	// One timeout covers the flight's whole life, queuing for a permit
	// included, so a flight never outlives RequestTimeout from its creation.
	// Shutdown relies on that bound: it drains requests for RequestTimeout
	// plus a few seconds and then closes the cache, which a flight that
	// restarted its clock after queuing could still be writing to.
	qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), config.RequestTimeout)
	defer cancel()

	limiter := config.UpstreamLimiter
	if err := f.acquirePermit(qctx, limiter); err != nil {
		// Abandoned (nobody is waiting, and the flight is already out of the
		// registry) or out of time before a permit freed up; either way there
		// is no upstream answer and nothing to cache.
		f.publish(fkey, queryOutcome{}, err)
		return
	}
	metrics.UpstreamInFlight.Inc()
	defer func() {
		metrics.UpstreamInFlight.Dec()
		if limiter != nil {
			<-limiter
		}
	}()

	outcome, err := fn(qctx)

	// Write before publishing the result, so a caller that has seen the
	// response can rely on the cache being populated.
	f.commit(qctx, cacheKey, outcome, err)
	f.publish(fkey, outcome, err)
}

// commitLocks serializes cache commits per key. A commit is the superseded
// check plus the write that follows it; they must happen as one step, or a
// regular flight could pass the check, stall, and land its older result on
// top of a refresh that took ownership of the entry and wrote in between.
// With the lock, either the regular commit finishes first (and the refresh,
// which marks ownership before querying and so commits later, overwrites it)
// or it sees the superseded mark and skips. Entries are reference-counted and
// dropped when unused; the lock is per key, so a slow cache write (Redis)
// only holds up commits for that same key. It orders commits within this
// process only — instances sharing Redis are not coordinated.
var (
	commitLocksMu sync.Mutex
	commitLocks   = make(map[string]*commitLock)
)

type commitLock struct {
	mu   sync.Mutex
	refs int // guarded by commitLocksMu
}

// lockCommit takes the commit lock for key and returns its release.
func lockCommit(key string) (unlock func()) {
	commitLocksMu.Lock()
	l, ok := commitLocks[key]
	if !ok {
		l = &commitLock{}
		commitLocks[key] = l
	}
	l.refs++
	commitLocksMu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		commitLocksMu.Lock()
		if l.refs--; l.refs == 0 {
			delete(commitLocks, key)
		}
		commitLocksMu.Unlock()
	}
}

// commit records the flight's result in the cache — the result, or a
// short-TTL negative marker for a stable not-found/denied error — unless an
// overlapping refresh owns the entry. See commitLocks for why the check and
// the write happen under one per-key lock.
func (f *flight) commit(ctx context.Context, cacheKey string, outcome queryOutcome, err error) {
	unlock := lockCommit(cacheKey)
	defer unlock()

	flightsMu.Lock()
	superseded := f.superseded
	flightsMu.Unlock()

	switch {
	case superseded:
	case err != nil:
		utils.CacheNegativeResult(ctx, config.CacheManager, cacheKey, err, config.NegativeCacheExpiration)
	default:
		if err := utils.SetToCache(ctx, config.CacheManager, cacheKey, outcome.body, config.CacheExpiration); err != nil {
			slog.WarnContext(ctx, "cache write error", "key", cacheKey, "err", err)
		}
	}
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
