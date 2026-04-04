package utils

import "errors"

// Sentinel errors shared across packages.
// Use errors.Is() to compare against these.
var (
	// ErrResourceNotFound is returned when a queried resource does not exist.
	ErrResourceNotFound = errors.New("resource not found")
	// ErrQueryDenied is returned when the registry denies the query.
	ErrQueryDenied = errors.New("the registry denied the query")
	// ErrDomainNotFound is returned when WHOIS data cannot be found or parsed.
	ErrDomainNotFound = errors.New("domain not found")
)
