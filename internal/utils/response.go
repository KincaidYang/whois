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

// ErrorResponse represents a standard error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// writeJSONError writes a JSON error response safely
func writeJSONError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}

// HandleQueryError handles common query errors with appropriate HTTP responses.
// Unexpected errors are logged in full but reported to the client with a
// generic message, so internal details such as upstream server addresses and
// network error strings do not leak.
func HandleQueryError(ctx context.Context, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrResourceNotFound), errors.Is(err, ErrDomainNotFound):
		writeJSONError(w, http.StatusNotFound, "Resource not found")
	case errors.Is(err, ErrQueryDenied):
		writeJSONError(w, http.StatusForbidden, "The registry denied the query")
	default:
		slog.ErrorContext(ctx, "query failed", "err", err)
		writeJSONError(w, http.StatusInternalServerError, "Query failed. Please try again later.")
	}
}

// HandleHTTPError handles different types of HTTP errors
func HandleHTTPError(w http.ResponseWriter, errorType ErrorType, message string) {
	var statusCode int

	switch errorType {
	case ErrorTypeNotFound:
		statusCode = http.StatusNotFound
		if message == "" {
			message = "Resource not found"
		}
	case ErrorTypeForbidden:
		statusCode = http.StatusForbidden
		if message == "" {
			message = "Access forbidden"
		}
	case ErrorTypeInternalServer:
		statusCode = http.StatusInternalServerError
		if message == "" {
			message = "Internal server error"
		}
	case ErrorTypeBadRequest:
		statusCode = http.StatusBadRequest
		if message == "" {
			message = "Bad request"
		}
	default:
		statusCode = http.StatusInternalServerError
		if message == "" {
			message = "Unknown error"
		}
	}

	writeJSONError(w, statusCode, message)
}

// HandleInternalError handles internal server errors. The error is logged in
// full; the client only sees a generic message.
func HandleInternalError(ctx context.Context, w http.ResponseWriter, err error) {
	slog.ErrorContext(ctx, "internal error", "err", err)
	writeJSONError(w, http.StatusInternalServerError, "Internal server error")
}
