package utils

import (
	"encoding/json"
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

// HandleQueryError handles common query errors with appropriate HTTP responses
func HandleQueryError(w http.ResponseWriter, err error) {
	switch err.Error() {
	case "resource not found", "domain not found":
		writeJSONError(w, http.StatusNotFound, "Resource not found")
	case "the registry denied the query":
		writeJSONError(w, http.StatusForbidden, "The registry denied the query")
	default:
		writeJSONError(w, http.StatusInternalServerError, err.Error())
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

// HandleInternalError handles internal server errors
func HandleInternalError(w http.ResponseWriter, err error) {
	writeJSONError(w, http.StatusInternalServerError, err.Error())
}
