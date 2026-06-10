package utils

import (
	"context"
	"testing"
	"time"
)

func TestMemoryCache(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryCache(100, 1*time.Second)

	// Test Set and Get
	err := cache.Set(ctx, "test-key", "test-value", 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to set cache: %v", err)
	}

	result, err := cache.Get(ctx, "test-key")
	if err != nil {
		t.Fatalf("Failed to get cache: %v", err)
	}

	if !result.Found {
		t.Fatal("Expected cache hit, got miss")
	}

	if result.Data != "test-value" {
		t.Fatalf("Expected 'test-value', got '%s'", result.Data)
	}

	// Test expiration
	err = cache.Set(ctx, "expire-key", "expire-value", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to set cache: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	result, err = cache.Get(ctx, "expire-key")
	if err != nil {
		t.Fatalf("Failed to get cache: %v", err)
	}

	if result.Found {
		t.Fatal("Expected cache miss after expiration, got hit")
	}

	// Test health
	if !cache.IsHealthy() {
		t.Fatal("Memory cache should always be healthy")
	}

	t.Log("✓ MemoryCache tests passed")
}

func TestFallbackCache(t *testing.T) {
	ctx := context.Background()

	// Create a memory cache as both primary and fallback for testing
	primary := NewMemoryCache(100, 1*time.Second)
	fallback := NewMemoryCache(100, 1*time.Second)

	cache := NewFallbackCache(primary, fallback)

	// Test Set and Get
	err := cache.Set(ctx, "test-key", "test-value", 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to set cache: %v", err)
	}

	result, err := cache.Get(ctx, "test-key")
	if err != nil {
		t.Fatalf("Failed to get cache: %v", err)
	}

	if !result.Found {
		t.Fatal("Expected cache hit, got miss")
	}

	if result.Data != "test-value" {
		t.Fatalf("Expected 'test-value', got '%s'", result.Data)
	}

	// Test health
	if !cache.IsHealthy() {
		t.Fatal("FallbackCache should be healthy when either cache is healthy")
	}

	t.Log("✓ FallbackCache tests passed")
}

func TestMemoryCacheMaxSize(t *testing.T) {
	ctx := context.Background()
	maxSize := 10
	cache := NewMemoryCache(maxSize, 1*time.Second)

	// Fill cache to max
	for i := 0; i < maxSize; i++ {
		err := cache.Set(ctx, string(rune('a'+i)), "value", 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to set cache: %v", err)
		}
	}

	// Try to add one more (should be silently ignored or oldest evicted)
	err := cache.Set(ctx, "overflow", "value", 5*time.Second)
	if err != nil {
		t.Fatalf("Set should not error even when full: %v", err)
	}

	t.Log("✓ MemoryCache max size tests passed")
}
