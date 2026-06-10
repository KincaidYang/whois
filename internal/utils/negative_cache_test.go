package utils

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNegativeKindForError(t *testing.T) {
	tests := []struct {
		err      error
		wantKind string
		wantOK   bool
	}{
		{ErrResourceNotFound, negNotFound, true},
		{ErrDomainNotFound, negNotFound, true},
		{ErrQueryDenied, negDenied, true},
		{context.DeadlineExceeded, "", false},
		{nil, "", false},
	}
	for _, tt := range tests {
		kind, ok := negativeKindForError(tt.err)
		if kind != tt.wantKind || ok != tt.wantOK {
			t.Errorf("negativeKindForError(%v) = (%q, %v); want (%q, %v)", tt.err, kind, ok, tt.wantKind, tt.wantOK)
		}
	}
}

func TestCacheNegativeResultAndHit(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryCache(10, time.Minute)

	// Transient error must not be cached.
	CacheNegativeResult(ctx, cache, "k-transient", context.DeadlineExceeded, time.Minute)
	if r, _ := cache.Get(ctx, "k-transient"); r.Found {
		t.Error("transient error should not be cached")
	}

	// Non-positive TTL disables caching.
	CacheNegativeResult(ctx, cache, "k-disabled", ErrResourceNotFound, 0)
	if r, _ := cache.Get(ctx, "k-disabled"); r.Found {
		t.Error("ttl<=0 should disable negative caching")
	}

	// Not-found is cached and recognised as a 404 negative hit.
	CacheNegativeResult(ctx, cache, "k-nf", ErrResourceNotFound, time.Minute)
	r, _ := cache.Get(ctx, "k-nf")
	if !r.Found {
		t.Fatal("expected negative marker to be cached")
	}
	w := httptest.NewRecorder()
	if !IsNegativeCacheHit(w, r.Data) {
		t.Fatal("expected IsNegativeCacheHit to recognise the marker")
	}
	if w.Code != 404 {
		t.Errorf("expected 404 for not-found marker, got %d", w.Code)
	}

	// Denied is cached and recognised as a 403 negative hit.
	CacheNegativeResult(ctx, cache, "k-denied", ErrQueryDenied, time.Minute)
	r, _ = cache.Get(ctx, "k-denied")
	w = httptest.NewRecorder()
	if !IsNegativeCacheHit(w, r.Data) {
		t.Fatal("expected denied marker to be recognised")
	}
	if w.Code != 403 {
		t.Errorf("expected 403 for denied marker, got %d", w.Code)
	}
}

func TestIsNegativeCacheHit_RealData(t *testing.T) {
	w := httptest.NewRecorder()
	if IsNegativeCacheHit(w, `{"Domain Name":"example.com"}`) {
		t.Error("real JSON payload must not be treated as a negative hit")
	}
	if IsNegativeCacheHit(w, "Domain Name: example.com\n") {
		t.Error("real WHOIS text must not be treated as a negative hit")
	}
}
