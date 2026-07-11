package handlers

import (
	"context"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/utils"
	"golang.org/x/sync/singleflight"
)

// sfGroup deduplicates concurrent upstream queries for the same cache key, so
// a burst of cache misses on one resource results in a single upstream request
// whose result is shared by all waiters.
var sfGroup singleflight.Group

// queryOutcome is the result of an upstream query, shared between concurrent
// requests waiting on the same singleflight key.
type queryOutcome struct {
	body        string
	contentType string
}

// dedupedQuery runs fn through sfGroup under the given key. The flight gets
// its own timeout, detached from the first caller's context, so one client
// disconnecting does not fail the other requests waiting on the same key —
// but each waiter honors its own context and stops waiting (releasing its
// concurrency slot) when that context ends, while the flight runs to
// completion and still populates the cache for later requests.
// Stable not-found/denied errors are negative-cached once per flight.
func dedupedQuery(ctx context.Context, key string, fn func(context.Context) (queryOutcome, error)) (queryOutcome, error) {
	ch := sfGroup.DoChan(key, func() (any, error) {
		qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), config.RequestTimeout)
		defer cancel()

		outcome, err := fn(qctx)
		if err != nil {
			utils.CacheNegativeResult(qctx, config.CacheManager, key, err, config.NegativeCacheExpiration)
			return nil, err
		}
		return outcome, nil
	})

	select {
	case res := <-ch:
		if res.Err != nil {
			return queryOutcome{}, res.Err
		}
		return res.Val.(queryOutcome), nil
	case <-ctx.Done():
		// The handler's defer frees its concurrency slot as soon as we
		// return, but the detached flight's upstream request is still
		// running. Hold a slot on its behalf until it completes, so
		// server.rateLimit stays a true cap on concurrent upstream work —
		// otherwise a client could disconnect repeatedly to stack detached
		// flights beyond the configured limit. (nil only in tests that
		// bypass config.Load.)
		if limiter := config.ConcurrencyLimiter; limiter != nil {
			go func() {
				limiter <- struct{}{}
				<-ch
				<-limiter
			}()
		}
		return queryOutcome{}, ctx.Err()
	}
}
