package utils

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

// requestIDKey is the context key under which the per-request ID is stored.
type requestIDKey struct{}

// WithRequestID returns a copy of ctx carrying the given request ID.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFromContext returns the request ID stored in ctx, if any.
func RequestIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIDKey{}).(string)
	return id, ok && id != ""
}

// NewRequestID generates a random 16-character hex request ID.
func NewRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is effectively unreachable; fall back to a
		// fixed marker rather than propagating an error for a log ID.
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}

// IsValidRequestID reports whether an inbound X-Request-ID value is safe to
// echo into logs and response headers: non-empty, at most 64 characters, and
// limited to [A-Za-z0-9._-] so it cannot inject log fields or header tricks.
func IsValidRequestID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}
