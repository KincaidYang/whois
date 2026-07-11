package utils

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"
)

// ErrorType represents different types of errors
type ErrorType int

const (
	ErrorTypeNotFound ErrorType = iota
	ErrorTypeForbidden
	ErrorTypeInternalServer
	ErrorTypeBadRequest
)

// problemTypeBase is the documentation URL prefix for problem type URIs
// (RFC 9457 section 3.1.1). Each error kind is an anchor in docs/errors.md.
const problemTypeBase = "https://github.com/KincaidYang/whois/blob/main/docs/errors.md"

// Problem is an RFC 9457 "problem details" error response, served as
// application/problem+json.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// writeProblem writes an RFC 9457 problem details response.
func writeProblem(w http.ResponseWriter, statusCode int, typeAnchor, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(Problem{
		Type:   problemTypeBase + "#" + typeAnchor,
		Title:  title,
		Status: statusCode,
		Detail: detail,
	})
}

// WriteUnauthorized writes the 401 problem response used when API key
// authentication is enabled and the request carries no valid key.
func WriteUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="whois"`)
	writeProblem(w, http.StatusUnauthorized, "unauthorized", "Authentication required",
		"Provide a valid API key via \"Authorization: Bearer <key>\" or \"X-API-Key: <key>\".")
}

// WriteRateLimited writes the 429 problem response used when the concurrency
// limiter rejects a request.
func WriteRateLimited(w http.ResponseWriter) {
	writeProblem(w, http.StatusTooManyRequests, "rate-limited",
		"Too many concurrent requests", "")
}

// WriteRateLimitedAfter writes the 429 problem response used when a per-key
// rate limit rejects a request, with a Retry-After header telling the client
// when the next token becomes available (rounded up to whole seconds).
func WriteRateLimitedAfter(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(math.Ceil(retryAfter.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeProblem(w, http.StatusTooManyRequests, "rate-limited",
		"Rate limit exceeded",
		"The API key's request budget is exhausted. Retry after the delay in the Retry-After header.")
}

// WriteRefreshRequiresAuth writes the 403 problem response returned when
// ?refresh is used on an instance without API key authentication: an open
// instance honoring forced refreshes would let anyone bypass the cache and
// hammer upstream registries.
func WriteRefreshRequiresAuth(w http.ResponseWriter) {
	writeProblem(w, http.StatusForbidden, "refresh-requires-auth",
		"Refresh requires authentication",
		"The ?refresh parameter is only honored when API key authentication (auth.keys) is enabled on this instance.")
}

// WriteMethodNotAllowed writes a 405 problem response carrying the Allow
// header listing the methods the endpoint supports.
func WriteMethodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeProblem(w, http.StatusMethodNotAllowed, "bad-request",
		"Method not allowed", "This endpoint only accepts "+allow+".")
}

// WriteBatchDisabled writes the 403 problem response returned when the batch
// endpoint is requested but batch.enabled is off (the default).
func WriteBatchDisabled(w http.ResponseWriter) {
	writeProblem(w, http.StatusForbidden, "batch-disabled",
		"Batch queries are disabled",
		"Batch queries are turned off on this instance. The operator can enable them with batch.enabled in the configuration.")
}

// WriteRateLimitedBatch writes the 429 problem response returned when a batch
// request asks for more items than the API key's per-minute budget could ever
// grant, so no Retry-After would make it succeed — the batch must shrink.
func WriteRateLimitedBatch(w http.ResponseWriter) {
	writeProblem(w, http.StatusTooManyRequests, "rate-limited",
		"Rate limit exceeded",
		"The batch exceeds the API key's per-minute request budget. Reduce the batch size.")
}

// HandleQueryError handles common query errors with appropriate HTTP responses.
// Unexpected errors are logged in full but reported to the client with a
// generic message, so internal details such as upstream server addresses and
// network error strings do not leak.
func HandleQueryError(ctx context.Context, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrResourceNotFound), errors.Is(err, ErrDomainNotFound):
		writeProblem(w, http.StatusNotFound, "not-found", "Resource not found", "")
	case errors.Is(err, ErrQueryDenied):
		writeProblem(w, http.StatusForbidden, "query-denied", "The registry denied the query", "")
	default:
		// A canceled or expired context is the request's own lifecycle
		// (client disconnect, request timeout), not an upstream failure;
		// log it below error level so disconnects don't page anyone.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			slog.WarnContext(ctx, "query aborted", "err", err)
		} else {
			slog.ErrorContext(ctx, "query failed", "err", err)
		}
		writeProblem(w, http.StatusInternalServerError, "query-failed",
			"Query failed", "Please try again later.")
	}
}

// HandleHTTPError handles different types of HTTP errors. message becomes the
// problem detail; the title is fixed per error type.
func HandleHTTPError(w http.ResponseWriter, errorType ErrorType, message string) {
	switch errorType {
	case ErrorTypeNotFound:
		writeProblem(w, http.StatusNotFound, "not-found", "Resource not found", message)
	case ErrorTypeForbidden:
		writeProblem(w, http.StatusForbidden, "query-denied", "Access forbidden", message)
	case ErrorTypeBadRequest:
		writeProblem(w, http.StatusBadRequest, "bad-request", "Bad request", message)
	default:
		writeProblem(w, http.StatusInternalServerError, "internal-error", "Internal server error", message)
	}
}

// HandleInternalError handles internal server errors. The error is logged in
// full; the client only sees a generic message.
func HandleInternalError(ctx context.Context, w http.ResponseWriter, err error) {
	slog.ErrorContext(ctx, "internal error", "err", err)
	writeProblem(w, http.StatusInternalServerError, "internal-error", "Internal server error", "")
}
