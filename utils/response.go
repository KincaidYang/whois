package utils

import (
	"fmt"
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

// HandleQueryError handles common query errors with appropriate HTTP responses
func HandleQueryError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")

	switch err.Error() {
	case "resource not found":
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error": "Resource not found"}`)
	case "domain not found":
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error": "Resource not found"}`)
	case "the registry denied the query":
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error": "The registry denied the query"}`)
	default:
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error": "`+err.Error()+`"}`)
	}
}

// HandleHTTPError handles different types of HTTP errors
func HandleHTTPError(w http.ResponseWriter, errorType ErrorType, message string) {
	w.Header().Set("Content-Type", "application/json")

	switch errorType {
	case ErrorTypeNotFound:
		w.WriteHeader(http.StatusNotFound)
		if message == "" {
			message = "Resource not found"
		}
	case ErrorTypeForbidden:
		w.WriteHeader(http.StatusForbidden)
		if message == "" {
			message = "Access forbidden"
		}
	case ErrorTypeInternalServer:
		w.WriteHeader(http.StatusInternalServerError)
		if message == "" {
			message = "Internal server error"
		}
	case ErrorTypeBadRequest:
		w.WriteHeader(http.StatusBadRequest)
		if message == "" {
			message = "Bad request"
		}
	default:
		w.WriteHeader(http.StatusInternalServerError)
		if message == "" {
			message = "Unknown error"
		}
	}

	fmt.Fprint(w, `{"error": "`+message+`"}`)
}

// HandleInternalError handles internal server errors
func HandleInternalError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
