package utils

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleHTTPError(t *testing.T) {
	tests := []struct {
		errorType  ErrorType
		message    string
		wantStatus int
		wantMsg    string
	}{
		{ErrorTypeNotFound, "not here", http.StatusNotFound, "not here"},
		{ErrorTypeNotFound, "", http.StatusNotFound, "Resource not found"},
		{ErrorTypeForbidden, "denied", http.StatusForbidden, "denied"},
		{ErrorTypeForbidden, "", http.StatusForbidden, "Access forbidden"},
		{ErrorTypeInternalServer, "oops", http.StatusInternalServerError, "oops"},
		{ErrorTypeInternalServer, "", http.StatusInternalServerError, "Internal server error"},
		{ErrorTypeBadRequest, "bad input", http.StatusBadRequest, "bad input"},
		{ErrorTypeBadRequest, "", http.StatusBadRequest, "Bad request"},
	}

	for _, tt := range tests {
		w := httptest.NewRecorder()
		HandleHTTPError(w, tt.errorType, tt.message)

		if w.Code != tt.wantStatus {
			t.Errorf("HandleHTTPError(%v, %q): status=%d, want %d", tt.errorType, tt.message, w.Code, tt.wantStatus)
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type=%q, want application/json", ct)
		}
		var body ErrorResponse
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Errorf("response body is not valid JSON: %v", err)
			continue
		}
		if body.Error != tt.wantMsg {
			t.Errorf("body.Error=%q, want %q", body.Error, tt.wantMsg)
		}
	}
}

func TestHandleQueryError(t *testing.T) {
	tests := []struct {
		err        error
		wantStatus int
	}{
		{ErrResourceNotFound, http.StatusNotFound},
		{ErrDomainNotFound, http.StatusNotFound},
		{ErrQueryDenied, http.StatusForbidden},
	}

	for _, tt := range tests {
		w := httptest.NewRecorder()
		HandleQueryError(context.Background(), w, tt.err)
		if w.Code != tt.wantStatus {
			t.Errorf("HandleQueryError(%v): status=%d, want %d", tt.err, w.Code, tt.wantStatus)
		}
	}
}

func TestHandleInternalError(t *testing.T) {
	w := httptest.NewRecorder()
	HandleInternalError(context.Background(), w, ErrResourceNotFound)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status=%d, want 500", w.Code)
	}
}

// TestHandleQueryErrorSanitizesUnexpectedErrors verifies that unexpected
// errors (network failures, upstream hostnames) are not leaked to the client.
func TestHandleQueryErrorSanitizesUnexpectedErrors(t *testing.T) {
	w := httptest.NewRecorder()
	HandleQueryError(context.Background(), w, errors.New("dial tcp whois.internal.example:43: connection refused"))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status=%d, want 500", w.Code)
	}
	var body ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if strings.Contains(body.Error, "whois.internal.example") {
		t.Errorf("error message leaks upstream host: %q", body.Error)
	}
	if body.Error != "Query failed. Please try again later." {
		t.Errorf("body.Error=%q, want generic message", body.Error)
	}
}

// TestHandleInternalErrorSanitizes verifies the client sees a generic message
// rather than the raw error text.
func TestHandleInternalErrorSanitizes(t *testing.T) {
	w := httptest.NewRecorder()
	HandleInternalError(context.Background(), w, errors.New("redis: connection pool timeout at 10.0.0.5:6379"))

	var body ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body.Error != "Internal server error" {
		t.Errorf("body.Error=%q, want %q", body.Error, "Internal server error")
	}
}

func TestHandleCacheResponse(t *testing.T) {
	w := httptest.NewRecorder()
	HandleCacheResponse(w, `{"domain":"example.com"}`, "application/json")

	if w.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type=%q, want application/json", ct)
	}
	if body := w.Body.String(); body != `{"domain":"example.com"}` {
		t.Errorf("body=%q", body)
	}
}

func TestHandleCacheResponse_DefaultContentType(t *testing.T) {
	w := httptest.NewRecorder()
	HandleCacheResponse(w, "raw whois text", "")
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type=%q, want application/json for empty contentType", ct)
	}
}
