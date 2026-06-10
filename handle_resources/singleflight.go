package handle_resources

import (
	"context"

	"github.com/KincaidYang/whois/config"
	"github.com/KincaidYang/whois/utils"
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
// disconnecting does not fail the other requests waiting on the same key.
// Stable not-found/denied errors are negative-cached once per flight.
func dedupedQuery(ctx context.Context, key string, fn func(context.Context) (queryOutcome, error)) (queryOutcome, error) {
	v, err, _ := sfGroup.Do(key, func() (any, error) {
		qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), config.RequestTimeout)
		defer cancel()

		outcome, err := fn(qctx)
		if err != nil {
			utils.CacheNegativeResult(qctx, config.CacheManager, key, err, config.NegativeCacheExpiration)
			return nil, err
		}
		return outcome, nil
	})
	if err != nil {
		return queryOutcome{}, err
	}
	return v.(queryOutcome), nil
}
