package utils

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KincaidYang/whois/metrics"
)

// Cache defines the interface for cache operations
type Cache interface {
	Get(ctx context.Context, key string) (CacheResult, error)
	Set(ctx context.Context, key string, value string, expiration time.Duration) error
	IsHealthy() bool
}

// cacheEntry represents a cached item with expiration
type cacheEntry struct {
	Value     string
	ExpiresAt time.Time
}

// MemoryCache implements Cache interface using in-memory storage
type MemoryCache struct {
	data          sync.Map
	maxSize       int
	cleanInterval time.Duration
	size          atomic.Int64
}

// NewMemoryCache creates a new memory cache instance
func NewMemoryCache(maxSize int, cleanInterval time.Duration) *MemoryCache {
	mc := &MemoryCache{
		maxSize:       maxSize,
		cleanInterval: cleanInterval,
	}

	// Start background cleaner
	go mc.startCleaner()

	return mc
}

// Get retrieves a value from memory cache
func (mc *MemoryCache) Get(ctx context.Context, key string) (CacheResult, error) {
	value, ok := mc.data.Load(key)
	if !ok {
		metrics.CacheRequestsTotal.WithLabelValues("memory", "miss").Inc()
		return CacheResult{Found: false}, nil
	}

	entry := value.(cacheEntry)

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		mc.data.Delete(key)
		mc.decrementSize()
		metrics.CacheRequestsTotal.WithLabelValues("memory", "miss").Inc()
		return CacheResult{Found: false}, nil
	}

	slog.Debug("cache hit", "backend", "memory", "key", key)
	metrics.CacheRequestsTotal.WithLabelValues("memory", "hit").Inc()
	return CacheResult{Data: entry.Value, Found: true}, nil
}

// Set stores a value in memory cache
func (mc *MemoryCache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	// Check size limit only for new entries
	if _, exists := mc.data.Load(key); !exists {
		if mc.size.Load() >= int64(mc.maxSize) {
			// Try to clean expired entries first
			mc.cleanExpired()

			// If still over limit, evict one arbitrary entry to make room
			if mc.size.Load() >= int64(mc.maxSize) {
				mc.evictOne()
			}
		}
	}

	entry := cacheEntry{
		Value:     value,
		ExpiresAt: time.Now().Add(expiration),
	}

	// Check if this is a new entry
	_, existed := mc.data.Load(key)
	mc.data.Store(key, entry)

	if !existed {
		mc.incrementSize()
	}

	return nil
}

// IsHealthy always returns true for memory cache
func (mc *MemoryCache) IsHealthy() bool {
	return true
}

// incrementSize atomically increments the size counter
func (mc *MemoryCache) incrementSize() {
	mc.size.Add(1)
}

// decrementSize atomically decrements the size counter
func (mc *MemoryCache) decrementSize() {
	mc.size.Add(-1)
}

// evictOne removes the first entry encountered in the cache.
// sync.Map iteration order is unspecified, giving effectively random eviction.
func (mc *MemoryCache) evictOne() {
	mc.data.Range(func(key, _ interface{}) bool {
		mc.data.Delete(key)
		mc.decrementSize()
		return false // stop after first entry
	})
}

// startCleaner runs a periodic cleanup of expired entries
func (mc *MemoryCache) startCleaner() {
	ticker := time.NewTicker(mc.cleanInterval)
	defer ticker.Stop()

	for range ticker.C {
		mc.cleanExpired()
	}
}

// cleanExpired removes all expired entries in a single pass
func (mc *MemoryCache) cleanExpired() {
	now := time.Now()
	mc.data.Range(func(key, value interface{}) bool {
		entry := value.(cacheEntry)
		if now.After(entry.ExpiresAt) {
			mc.data.Delete(key)
			mc.decrementSize()
		}
		return true
	})
}

// FallbackCache implements Cache with primary and fallback caches
type FallbackCache struct {
	primary  Cache
	fallback Cache
}

// NewFallbackCache creates a new fallback cache
func NewFallbackCache(primary, fallback Cache) *FallbackCache {
	return &FallbackCache{
		primary:  primary,
		fallback: fallback,
	}
}

// Get tries primary cache first, then fallback.
// Falls through to fallback on primary error OR miss, so that entries written
// to memory-only during a Redis outage are still served after Redis recovers.
func (fc *FallbackCache) Get(ctx context.Context, key string) (CacheResult, error) {
	if fc.primary.IsHealthy() {
		result, err := fc.primary.Get(ctx, key)
		if err == nil && result.Found {
			return result, nil
		}
		// Primary missed or errored — fall through to fallback
	}

	return fc.fallback.Get(ctx, key)
}

// Set attempts to write to both caches
func (fc *FallbackCache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	var primaryErr error

	// Try primary cache
	if fc.primary.IsHealthy() {
		primaryErr = fc.primary.Set(ctx, key, value, expiration)
	}

	// Always set to fallback
	fallbackErr := fc.fallback.Set(ctx, key, value, expiration)

	// Return primary error if exists, otherwise fallback error
	if primaryErr != nil {
		return primaryErr
	}
	return fallbackErr
}

// IsHealthy returns true if either cache is healthy
func (fc *FallbackCache) IsHealthy() bool {
	return fc.primary.IsHealthy() || fc.fallback.IsHealthy()
}

// IsPrimaryHealthy returns true if the primary cache (Redis) is healthy
func (fc *FallbackCache) IsPrimaryHealthy() bool {
	return fc.primary.IsHealthy()
}
