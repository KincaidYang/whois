package utils

import (
	"container/list"
	"context"
	"errors"
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
// so size accounting (len(items), curBytes) is always consistent.
type MemoryCache struct {
	mu            sync.Mutex
	items         map[string]*list.Element // key -> element holding *cacheEntry
	order         *list.List               // front = most recently used
	maxSize       int
	maxBytes      int64 // 0 = no byte budget, only maxSize applies
	curBytes      int64
	cleanInterval time.Duration
	done          chan struct{}
	closeOnce     sync.Once
}

// NewMemoryCache creates a new memory cache instance. maxBytes bounds the
// total size of stored keys+values; 0 disables the byte budget (maxSize
// still applies). Without it, a workload heavy in large entries (e.g. ?raw
// WHOIS text, or unparsed TLDs that wrap the whole raw response) can reach
// maxSize entries at up to ~2 MiB each before the count-based limit alone
// would evict anything.
func NewMemoryCache(maxSize int, cleanInterval time.Duration, maxBytes int64) *MemoryCache {
	mc := &MemoryCache{
		items:         make(map[string]*list.Element),
		order:         list.New(),
		maxSize:       maxSize,
		maxBytes:      maxBytes,
		cleanInterval: cleanInterval,
		done:          make(chan struct{}),
	}

	// Start background cleaner
	go mc.startCleaner()

	return mc
}

// entrySize is the byte cost charged against maxBytes for one entry: the key
// and value themselves, not the map/list bookkeeping overhead around them.
func entrySize(key, value string) int64 {
	return int64(len(key)) + int64(len(value))
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
	return CacheResult{Data: entry.Value, Found: true, ExpiresAt: entry.ExpiresAt}, nil
}

// Set stores a value in memory cache
func (mc *MemoryCache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	expiresAt := time.Now().Add(expiration)

	// Update existing entry in place and promote it. The entry count doesn't
	// change, so maxSize is never re-checked here — only the byte budget,
	// which a larger new value can still push over.
	if elem, ok := mc.items[key]; ok {
		entry := elem.Value.(*cacheEntry)
		mc.curBytes += entrySize(key, value) - entrySize(key, entry.Value)
		entry.Value = value
		entry.ExpiresAt = expiresAt
		mc.order.MoveToFront(elem)
		mc.evictOverBudget()
		return nil
	}

	// New entry: evict the least recently used items until there is room for
	// it (both the entry-count and, when set, the byte-budget limit).
	newSize := entrySize(key, value)
	mc.evictForInsert(newSize)

	elem := mc.order.PushFront(&cacheEntry{
		Key:       key,
		Value:     value,
		ExpiresAt: expiresAt,
	})
	mc.items[key] = elem
	mc.curBytes += newSize

	return nil
}

// evictForInsert makes room for one new entry of newSize not yet present in
// the cache: evicts LRU entries until adding it would stay under both
// maxSize and maxBytes. newSize must be counted against the budget here —
// checking curBytes alone (the pre-insert total) would let the post-insert
// total exceed maxBytes with no eviction ever triggered for it. May evict
// down to zero entries. Callers must hold mc.mu.
func (mc *MemoryCache) evictForInsert(newSize int64) {
	for len(mc.items) > 0 {
		overCount := len(mc.items) >= mc.maxSize
		overBytes := mc.maxBytes > 0 && mc.curBytes+newSize > mc.maxBytes
		if !overCount && !overBytes {
			return
		}
		mc.evictOldest()
	}
}

// evictOverBudget evicts LRU entries, other than the one just updated (which
// MoveToFront has already put at the front, safe from evictOldest's
// order.Back() as long as another entry remains), until under maxBytes. A
// single updated entry larger than maxBytes by itself is kept rather than
// evicted against itself. Callers must hold mc.mu.
func (mc *MemoryCache) evictOverBudget() {
	for len(mc.items) > 1 && mc.maxBytes > 0 && mc.curBytes > mc.maxBytes {
		mc.evictOldest()
	}
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
	mc.curBytes -= entrySize(entry.Key, entry.Value)
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

// deleter is implemented by cache backends that can remove entries outright.
// FallbackCache type-asserts primary to it to purge stale entries left over
// from an outage (see the dirty-key tracking below); a backend that doesn't
// implement it just never gets flushed. Not part of the Cache interface
// itself, the same way Close is handled via io.Closer: most callers don't
// need it.
type deleter interface {
	Del(ctx context.Context, keys ...string) error
}

// maxDirtyKeys bounds the dirty-key set FallbackCache tracks during a primary
// outage. Once an outage has touched this many distinct keys, further writes
// stop being tracked — the guarantee below degrades, but the set cannot grow
// without bound across a long outage. It matches the in-memory cache's own
// default entry cap, which is already the practical ceiling on how many
// distinct keys one instance handles.
const maxDirtyKeys = 10000

// FallbackCache implements Cache with primary and fallback caches
type FallbackCache struct {
	primary  Cache
	fallback Cache

	// dirty tracks keys written to fallback only, because primary was down
	// at the time. Once primary is healthy again, those keys still hold
	// their pre-outage value there — stale, but not expired — and would
	// shadow the newer fallback value in Get until that value's original TTL
	// runs out. flushDirty purges them from primary so Get falls through to
	// fallback immediately instead of waiting out the TTL.
	dirtyMu sync.Mutex
	dirty   map[string]struct{}
}

// NewFallbackCache creates a new fallback cache
func NewFallbackCache(primary, fallback Cache) *FallbackCache {
	return &FallbackCache{
		primary:  primary,
		fallback: fallback,
		dirty:    make(map[string]struct{}),
	}
}

// Get tries primary cache first, then fallback.
// Falls through to fallback on primary error OR miss, so that entries written
// to memory-only during a Redis outage are still served after Redis recovers.
func (fc *FallbackCache) Get(ctx context.Context, key string) (CacheResult, error) {
	if fc.primary.IsHealthy() {
		fc.flushDirty(ctx)
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

	if fc.primary.IsHealthy() {
		primaryErr = fc.primary.Set(ctx, key, value, expiration)
		fc.flushDirty(ctx)
	} else {
		// Primary won't see this write; remember the key so it gets purged
		// from primary once healthy again, instead of shadowing this value
		// with whatever primary still holds from before the outage.
		fc.markDirty(key)
	}

	// Always set to fallback
	fallbackErr := fc.fallback.Set(ctx, key, value, expiration)

	// Return primary error if exists, otherwise fallback error
	if primaryErr != nil {
		return primaryErr
	}
	return fallbackErr
}

// markDirty records key as written to fallback only. Callers must not hold
// fc.dirtyMu.
func (fc *FallbackCache) markDirty(key string) {
	fc.dirtyMu.Lock()
	defer fc.dirtyMu.Unlock()
	if len(fc.dirty) >= maxDirtyKeys {
		return
	}
	fc.dirty[key] = struct{}{}
}

// flushDirty purges primary's copy of every dirty key, so a stale pre-outage
// value there stops shadowing the newer one already in fallback. A short,
// caller-independent timeout bounds the cost on the request that happens to
// trigger the flush; failure just leaves the keys dirty for the next attempt.
func (fc *FallbackCache) flushDirty(ctx context.Context) {
	del, ok := fc.primary.(deleter)
	if !ok {
		return
	}

	fc.dirtyMu.Lock()
	if len(fc.dirty) == 0 {
		fc.dirtyMu.Unlock()
		return
	}
	keys := make([]string, 0, len(fc.dirty))
	for k := range fc.dirty {
		keys = append(keys, k)
	}
	fc.dirtyMu.Unlock()

	delCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := del.Del(delCtx, keys...); err != nil {
		slog.WarnContext(ctx, "failed to purge stale primary cache entries after recovery", "err", err)
		return
	}

	fc.dirtyMu.Lock()
	for _, k := range keys {
		delete(fc.dirty, k)
	}
	fc.dirtyMu.Unlock()
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
	var errs []error
	if c, ok := fc.primary.(io.Closer); ok {
		errs = append(errs, c.Close())
	}
	if c, ok := fc.fallback.(io.Closer); ok {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}
