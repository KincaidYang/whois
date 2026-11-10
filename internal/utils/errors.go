package utils

import (
	"errors"
	"fmt"
	"time"
)

// Sentinel errors shared across packages.
// Use errors.Is() to compare against these.
var (
	// ErrResourceNotFound is returned when a queried resource does not exist.
	ErrResourceNotFound = errors.New("resource not found")
	// ErrQueryDenied is returned when the registry denies the query.
	ErrQueryDenied = errors.New("the registry denied the query")
	// ErrDomainNotFound is returned when WHOIS data cannot be found or parsed.
	ErrDomainNotFound = errors.New("domain not found")
	// ErrUpstreamBusy is returned when a query's deadline passed while it was
	// still waiting for an upstream permit (server.upstreamLimit).
	ErrUpstreamBusy = errors.New("too many concurrent upstream queries")
	// ErrUpstreamRateLimited is matched by every UpstreamRateLimitedError.
	ErrUpstreamRateLimited = errors.New("the registry is rate limiting queries")
)

// UpstreamRateLimitedError is returned when the upstream registry answered
// HTTP 429: it is throttling this instance's address. RetryAfter is the delay
// the registry asked for, or 0 when it gave none.
type UpstreamRateLimitedError struct {
	RetryAfter time.Duration
}

func (e *UpstreamRateLimitedError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("%v (retry after %s)", ErrUpstreamRateLimited, e.RetryAfter)
	}
	return ErrUpstreamRateLimited.Error()
}

// Is makes errors.Is(err, ErrUpstreamRateLimited) match.
func (e *UpstreamRateLimitedError) Is(target error) bool {
	return target == ErrUpstreamRateLimited
}
