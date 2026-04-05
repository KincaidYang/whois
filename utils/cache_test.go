package utils

import (
	"context"
	"testing"
	"time"
)

func TestSetToCache_String(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryCache(10, time.Minute)

	err := SetToCache(ctx, cache, "k1", "hello", time.Minute)
	if err != nil {
		t.Fatalf("SetToCache string: %v", err)
	}

	result, err := GetFromCache(ctx, cache, "k1")
	if err != nil {
		t.Fatalf("GetFromCache: %v", err)
	}
	if !result.Found {
		t.Fatal("expected cache hit")
	}
	if result.Data != "hello" {
		t.Errorf("got %q, want %q", result.Data, "hello")
	}
}

func TestSetToCache_Struct(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryCache(10, time.Minute)

	type payload struct {
		Name string `json:"name"`
	}
	err := SetToCache(ctx, cache, "k2", payload{Name: "test"}, time.Minute)
	if err != nil {
		t.Fatalf("SetToCache struct: %v", err)
	}

	result, err := GetFromCache(ctx, cache, "k2")
	if err != nil {
		t.Fatalf("GetFromCache: %v", err)
	}
	if !result.Found {
		t.Fatal("expected cache hit")
	}
	if result.Data != `{"name":"test"}` {
		t.Errorf("got %q, want %q", result.Data, `{"name":"test"}`)
	}
}

func TestGetFromCache_Miss(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryCache(10, time.Minute)

	result, err := GetFromCache(ctx, cache, "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Found {
		t.Error("expected cache miss, got hit")
	}
}
