package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KincaidYang/whois/config"
	"github.com/KincaidYang/whois/handle_resources"
)

func TestIsASN(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"AS12345", true},
		{"as12345", true},
		{"asn67890", true},
		{"ASN67890", true},
		{"12345", true},
		{"ASD12345", false},
		{"asn", false},
		{"", false},
	}

	for _, test := range tests {
		result := isASN(test.input)
		if result != test.expected {
			t.Errorf("isASN(%q) = %v; want %v", test.input, result, test.expected)
		}
	}
}

func TestIsDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"sub.sub.example.com", true},
		{"-example.com", false},
		{"example-.com", false},
		{"example..com", false},
		{"example", false},
		{"123.com", true},
		{"example.c", false},    // TLD too short
		{"exa_mple.com", false}, // Invalid character
	}

	for _, test := range tests {
		result := isDomain(test.input)
		if result != test.expected {
			t.Errorf("isDomain(%q) = %v; want %v", test.input, result, test.expected)
		}
	}
}

func TestHandlerBadRequest(t *testing.T) {
	req := httptest.NewRequest("GET", "/not_a_valid_input!!", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandlerRateLimit(t *testing.T) {
	cap := cap(config.ConcurrencyLimiter)
	for i := 0; i < cap; i++ {
		config.ConcurrencyLimiter <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap; i++ {
			<-config.ConcurrencyLimiter
		}
	}()

	req := httptest.NewRequest("GET", "/example.com", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
}

func TestHandlerCacheHit(t *testing.T) {
	domain := "cachehittest99999.cn"
	key := "whois:" + domain
	cached := `{"domainName":"cachehittest99999.cn","creationDate":"2020-01-01T00:00:00Z"}`
	ctx := context.Background()
	if err := config.CacheManager.Set(ctx, key, cached, time.Minute); err != nil {
		t.Fatalf("failed to seed cache: %v", err)
	}

	req := httptest.NewRequest("GET", "/"+domain, nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "cachehittest99999.cn") {
		t.Errorf("response body missing cached domain: %s", w.Body.String())
	}
}

func TestHandleHealth(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handle_resources.HandleHealth(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type: got %q", ct)
	}
}

func TestHandleReady(t *testing.T) {
	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	handle_resources.HandleReady(w, req)
	// 200 or 503 are both valid depending on Redis availability
	if w.Code != http.StatusOK && w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 200 or 503, got %d", w.Code)
	}
}

func TestHandleInfo(t *testing.T) {
	req := httptest.NewRequest("GET", "/info", nil)
	w := httptest.NewRecorder()
	handle_resources.HandleInfo(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "goVersion") {
		t.Errorf("response missing goVersion field: %s", body)
	}
}
