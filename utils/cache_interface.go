package utils

import (
	"context"
	"log"
	"sync"
	"time"
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
	mu            sync.RWMutex
	size          int
}

// NewMemoryCache creates a new memory cache instance
func NewMemoryCache(maxSize int, cleanInterval time.Duration) *MemoryCache {
	mc := &MemoryCache{
		maxSize:       maxSize,
		cleanInterval: cleanInterval,
		size:          0,
	}

	// Start background cleaner
	go mc.startCleaner()

	return mc
}

// Get retrieves a value from memory cache
func (mc *MemoryCache) Get(ctx context.Context, key string) (CacheResult, error) {
	value, ok := mc.data.Load(key)
	if !ok {
		return CacheResult{Found: false}, nil
	}

	entry := value.(cacheEntry)

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		mc.data.Delete(key)
		mc.decrementSize()
		return CacheResult{Found: false}, nil
	}

	log.Printf("Serving cached result from memory for key: %s\n", key)
	return CacheResult{Data: entry.Value, Found: true}, nil
}

// Set stores a value in memory cache
func (mc *MemoryCache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	// Check size limit
	if _, exists := mc.data.Load(key); !exists {
		mc.mu.RLock()
		currentSize := mc.size
		mc.mu.RUnlock()

		if currentSize >= mc.maxSize {
			// Try to clean expired entries first
			mc.cleanExpired()

			mc.mu.RLock()
			currentSize = mc.size
			mc.mu.RUnlock()

			// If still over limit, don't cache
			if currentSize >= mc.maxSize {
				return nil
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

// incrementSize safely increments the size counter
func (mc *MemoryCache) incrementSize() {
	mc.mu.Lock()
	mc.size++
	mc.mu.Unlock()
}

// decrementSize safely decrements the size counter
func (mc *MemoryCache) decrementSize() {
	mc.mu.Lock()
	if mc.size > 0 {
		mc.size--
	}
	mc.mu.Unlock()
}

// startCleaner runs a periodic cleanup of expired entries
func (mc *MemoryCache) startCleaner() {
	ticker := time.NewTicker(mc.cleanInterval)
	defer ticker.Stop()

	for range ticker.C {
		mc.cleanExpired()
	}
}

// cleanExpired removes all expired entries
func (mc *MemoryCache) cleanExpired() {
	now := time.Now()
	keysToDelete := make([]string, 0)

	mc.data.Range(func(key, value interface{}) bool {
		entry := value.(cacheEntry)
		if now.After(entry.ExpiresAt) {
			keysToDelete = append(keysToDelete, key.(string))
		}
		return true
	})

	for _, key := range keysToDelete {
		mc.data.Delete(key)
		mc.decrementSize()
	}
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

// Get tries primary cache first, then fallback
func (fc *FallbackCache) Get(ctx context.Context, key string) (CacheResult, error) {
	// Try primary cache if healthy
	if fc.primary.IsHealthy() {
		result, err := fc.primary.Get(ctx, key)
		if err == nil {
			// Primary cache worked (hit or miss), return the result
			// No need to check fallback since we do dual-write
			return result, nil
		}
		// Primary cache had an error, fall through to fallback
	}

	// Primary unhealthy or errored, try fallback cache
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
