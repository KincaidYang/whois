package utils

import (
	"container/list"
	"context"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/KincaidYang/whois/internal/metrics"
)

// Cache defines the interface for cache operations
type Cache interface {
	Get(ctx context.Context, key string) (CacheResult, error)
	Set(ctx context.Context, key string, value string, expiration time.Duration) error
	IsHealthy() bool
}

// cacheEntry represents a cached item with expiration. It is stored as the
// value of a list element so the entry can be reached from both the lookup
// map and the LRU ordering list.
type cacheEntry struct {
	Key       string
	Value     string
	ExpiresAt time.Time
}

// MemoryCache implements Cache interface using in-memory storage with LRU
// eviction. A single mutex guards both the lookup map and the recency list,
// so size accounting (len(items)) is always consistent.
type MemoryCache struct {
	mu            sync.Mutex
	items         map[string]*list.Element // key -> element holding *cacheEntry
	order         *list.List               // front = most recently used
	maxSize       int
	cleanInterval time.Duration
	done          chan struct{}
	closeOnce     sync.Once
}

// NewMemoryCache creates a new memory cache instance
func NewMemoryCache(maxSize int, cleanInterval time.Duration) *MemoryCache {
	mc := &MemoryCache{
		items:         make(map[string]*list.Element),
		order:         list.New(),
		maxSize:       maxSize,
		cleanInterval: cleanInterval,
		done:          make(chan struct{}),
	}

	// Start background cleaner
	go mc.startCleaner()

	return mc
}

// Close stops the background cleaner goroutine. Safe to call multiple times.
func (mc *MemoryCache) Close() error {
	mc.closeOnce.Do(func() { close(mc.done) })
	return nil
}

// Get retrieves a value from memory cache
func (mc *MemoryCache) Get(ctx context.Context, key string) (CacheResult, error) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	elem, ok := mc.items[key]
	if !ok {
		metrics.CacheRequestsTotal.WithLabelValues("memory", "miss").Inc()
		return CacheResult{Found: false}, nil
	}

	entry := elem.Value.(*cacheEntry)

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		mc.removeElement(elem)
		metrics.CacheRequestsTotal.WithLabelValues("memory", "miss").Inc()
		return CacheResult{Found: false}, nil
	}

	// Mark as most recently used
	mc.order.MoveToFront(elem)

	slog.Debug("cache hit", "backend", "memory", "key", key)
	metrics.CacheRequestsTotal.WithLabelValues("memory", "hit").Inc()
	return CacheResult{Data: entry.Value, Found: true}, nil
}

// Set stores a value in memory cache
func (mc *MemoryCache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	expiresAt := time.Now().Add(expiration)

	// Update existing entry in place and promote it.
	if elem, ok := mc.items[key]; ok {
		entry := elem.Value.(*cacheEntry)
		entry.Value = value
		entry.ExpiresAt = expiresAt
		mc.order.MoveToFront(elem)
		return nil
	}

	// New entry: evict the least recently used item if at capacity.
	if len(mc.items) >= mc.maxSize {
		mc.evictOldest()
	}

	elem := mc.order.PushFront(&cacheEntry{
		Key:       key,
		Value:     value,
		ExpiresAt: expiresAt,
	})
	mc.items[key] = elem

	return nil
}

// IsHealthy always returns true for memory cache
func (mc *MemoryCache) IsHealthy() bool {
	return true
}

// removeElement deletes an element from both the map and the order list.
// Callers must hold mc.mu.
func (mc *MemoryCache) removeElement(elem *list.Element) {
	entry := elem.Value.(*cacheEntry)
	mc.order.Remove(elem)
	delete(mc.items, entry.Key)
}

// evictOldest removes the least recently used entry. Callers must hold mc.mu.
func (mc *MemoryCache) evictOldest() {
	elem := mc.order.Back()
	if elem == nil {
		return
	}
	mc.removeElement(elem)
	metrics.CacheEvictionsTotal.WithLabelValues("memory").Inc()
}

// startCleaner runs a periodic cleanup of expired entries until Close is called
func (mc *MemoryCache) startCleaner() {
	ticker := time.NewTicker(mc.cleanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mc.cleanExpired()
		case <-mc.done:
			return
		}
	}
}

// cleanExpired removes all expired entries in a single pass
func (mc *MemoryCache) cleanExpired() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	now := time.Now()
	for elem := mc.order.Back(); elem != nil; {
		prev := elem.Prev()
		if now.After(elem.Value.(*cacheEntry).ExpiresAt) {
			mc.removeElement(elem)
		}
		elem = prev
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

// Close stops background goroutines of the underlying caches that support it.
func (fc *FallbackCache) Close() error {
	if c, ok := fc.primary.(io.Closer); ok {
		c.Close()
	}
	if c, ok := fc.fallback.(io.Closer); ok {
		c.Close()
	}
	return nil
}
