package utils

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
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
		slog.ErrorContext(ctx, "query failed", "err", err)
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
