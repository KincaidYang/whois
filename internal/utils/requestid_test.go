package utils

import (
	"context"
	"strings"
	"testing"
)

func TestNewRequestID(t *testing.T) {
	a, b := NewRequestID(), NewRequestID()
	if len(a) != 16 || len(b) != 16 {
		t.Fatalf("expected 16-char IDs, got %q and %q", a, b)
	}
	if a == b {
		t.Errorf("two generated IDs collided: %q", a)
	}
}

func TestIsValidRequestID(t *testing.T) {
	valid := []string{"abc123", "trace-id_1.2", strings.Repeat("a", 64)}
	for _, id := range valid {
		if !IsValidRequestID(id) {
			t.Errorf("IsValidRequestID(%q) = false, want true", id)
		}
	}
	invalid := []string{"", "has space", "new\nline", "emoji✨", strings.Repeat("a", 65)}
	for _, id := range invalid {
		if IsValidRequestID(id) {
			t.Errorf("IsValidRequestID(%q) = true, want false", id)
		}
	}
}

func TestRequestIDContextRoundTrip(t *testing.T) {
	ctx := context.Background()
	if _, ok := RequestIDFromContext(ctx); ok {
		t.Fatal("empty context should carry no request ID")
	}
	ctx = WithRequestID(ctx, "abc123")
	id, ok := RequestIDFromContext(ctx)
	if !ok || id != "abc123" {
		t.Errorf("round trip failed: got %q, %v", id, ok)
	}
	// Values must survive WithoutCancel, since singleflight queries detach
	// from the caller's cancellation but should keep the request ID.
	id, ok = RequestIDFromContext(context.WithoutCancel(ctx))
	if !ok || id != "abc123" {
		t.Errorf("WithoutCancel dropped request ID: got %q, %v", id, ok)
	}
}
