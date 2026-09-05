package utils

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// stubCache is a Cache whose health, contents and errors are scripted, so
// FallbackCache routing can be asserted without a real backend.
type stubCache struct {
	healthy bool
	data    map[string]string
	setErr  error
	delErr  error
	sets    int
	closed  int
	dels    []string // keys passed to Del, across all calls, in order
}

func (s *stubCache) Get(ctx context.Context, key string) (CacheResult, error) {
	if v, ok := s.data[key]; ok {
		return CacheResult{Data: v, Found: true}, nil
	}
	return CacheResult{Found: false}, nil
}

func (s *stubCache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	s.sets++
	if s.setErr != nil {
		return s.setErr
	}
	if s.data == nil {
		s.data = make(map[string]string)
	}
	s.data[key] = value
	return nil
}

func (s *stubCache) IsHealthy() bool { return s.healthy }

// Del implements the unexported deleter interface FallbackCache checks for,
// so stubCache can stand in as a primary in dirty-key-flush tests.
func (s *stubCache) Del(ctx context.Context, keys ...string) error {
	s.dels = append(s.dels, keys...)
	if s.delErr != nil {
		return s.delErr
	}
	for _, k := range keys {
		delete(s.data, k)
	}
	return nil
}

func (s *stubCache) Close() error {
	s.closed++
	return nil
}

func TestMemoryCacheLRUEviction(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryCache(2, time.Hour, 0)
	defer func() { _ = cache.Close() }()

	mustSet := func(k, v string) {
		t.Helper()
		if err := cache.Set(ctx, k, v, time.Hour); err != nil {
			t.Fatalf("Set(%q): %v", k, err)
		}
	}

	mustSet("a", "1")
	mustSet("b", "2")

	// Touch "a" so "b" becomes the least recently used entry.
	if r, _ := cache.Get(ctx, "a"); !r.Found {
		t.Fatal("expected hit for a")
	}

	// Inserting at capacity must evict the LRU entry ("b"), not "a".
	mustSet("c", "3")
	if r, _ := cache.Get(ctx, "b"); r.Found {
		t.Error("b should have been evicted as least recently used")
	}
	if r, _ := cache.Get(ctx, "a"); !r.Found {
		t.Error("a was recently used and must survive eviction")
	}
	if r, _ := cache.Get(ctx, "c"); !r.Found {
		t.Error("newly inserted c must be present")
	}

	// Updating an existing key at capacity replaces in place: no eviction.
	mustSet("a", "1-updated")
	if r, _ := cache.Get(ctx, "a"); !r.Found || r.Data != "1-updated" {
		t.Errorf("a = %+v, want updated value", r)
	}
	if r, _ := cache.Get(ctx, "c"); !r.Found {
		t.Error("updating a must not evict c")
	}
}

// TestMemoryCacheByteBudget verifies entries are evicted LRU once the byte
// budget is exceeded, even though the entry-count limit (maxSize) alone
// would allow many more — the scenario a large ?raw or unparsed-TLD response
// can hit well before hitting maxSize.
func TestMemoryCacheByteBudget(t *testing.T) {
	ctx := context.Background()
	// maxSize is generous (100); maxBytes is the real constraint here.
	cache := NewMemoryCache(100, time.Hour, 20)
	defer func() { _ = cache.Close() }()

	mustSet := func(k, v string) {
		t.Helper()
		if err := cache.Set(ctx, k, v, time.Hour); err != nil {
			t.Fatalf("Set(%q): %v", k, err)
		}
	}

	// Each of a/b/c/d costs 6 bytes (1-byte key + 5-byte value). a, b, c fit
	// in the 20-byte budget (18 total); inserting d would reach 24, over
	// budget, so the least-recently-used entry — a, set first and never
	// touched again — must be evicted to make room.
	mustSet("a", "12345")
	mustSet("b", "12345")
	mustSet("c", "12345")
	mustSet("d", "12345")

	if r, _ := cache.Get(ctx, "a"); r.Found {
		t.Error("a should have been evicted as the least recently used entry once the byte budget was exceeded")
	}
	for _, k := range []string{"b", "c", "d"} {
		if r, _ := cache.Get(ctx, k); !r.Found {
			t.Errorf("%s should still be present", k)
		}
	}
}

// TestMemoryCacheByteBudgetEvictsOnGrowingUpdate verifies that updating an
// existing key with a larger value can push the total over budget too, not
// just inserting a new key — and that eviction then takes other entries
// rather than the one just written.
func TestMemoryCacheByteBudgetEvictsOnGrowingUpdate(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryCache(100, time.Hour, 20)
	defer func() { _ = cache.Close() }()

	if err := cache.Set(ctx, "a", "12345", time.Hour); err != nil { // 6 bytes
		t.Fatalf("Set(a): %v", err)
	}
	if err := cache.Set(ctx, "b", "12345", time.Hour); err != nil { // 6 bytes; total 12
		t.Fatalf("Set(b): %v", err)
	}

	// Growing "a" alone to 17 bytes (1-byte key + 16-byte value) brings the
	// total to 23 (17 + the still-unchanged 6 for "b"), over the 20-byte
	// budget: "b" — the only other entry, and the LRU one — must be evicted,
	// while "a" survives its own update.
	bigValue := strings.Repeat("x", 16)
	if err := cache.Set(ctx, "a", bigValue, time.Hour); err != nil {
		t.Fatalf("Set(a, grown): %v", err)
	}

	if r, _ := cache.Get(ctx, "b"); r.Found {
		t.Error("b should have been evicted when growing a pushed the total over budget")
	}
	if r, _ := cache.Get(ctx, "a"); !r.Found || r.Data != bigValue {
		t.Errorf("a = %+v, want it to survive its own update with the grown value", r)
	}
}

// TestMemoryCacheByteBudgetKeepsOversizedSingleEntry verifies a single entry
// larger than the byte budget is kept rather than evicted against itself.
func TestMemoryCacheByteBudgetKeepsOversizedSingleEntry(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryCache(100, time.Hour, 5)
	defer func() { _ = cache.Close() }()

	if err := cache.Set(ctx, "big", "this value alone exceeds the budget", time.Hour); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if r, _ := cache.Get(ctx, "big"); !r.Found {
		t.Error("an oversized single entry must still be stored, not evicted against itself")
	}
}

func TestMemoryCacheCleanExpired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		cache := NewMemoryCache(10, time.Hour, 0) // cleaner ticker never fires in-test
		defer func() { _ = cache.Close() }()

		if err := cache.Set(ctx, "live", "v", time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := cache.Set(ctx, "dead1", "v", time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if err := cache.Set(ctx, "dead2", "v", time.Millisecond); err != nil {
			t.Fatal(err)
		}
		// Fake time, so this is instant and the TTLs above expire exactly.
		time.Sleep(10 * time.Millisecond)

		cache.cleanExpired()

		cache.mu.Lock()
		n := len(cache.items)
		cache.mu.Unlock()
		if n != 1 {
			t.Errorf("after cleanExpired: %d entries, want 1 (only the live one)", n)
		}
		if r, _ := cache.Get(ctx, "live"); !r.Found {
			t.Error("live entry must survive the sweep")
		}
	})
}

func TestMemoryCacheCleanerLoop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		cache := NewMemoryCache(10, 20*time.Millisecond, 0)
		defer func() { _ = cache.Close() }()

		if err := cache.Set(ctx, "dead", "v", time.Millisecond); err != nil {
			t.Fatal(err)
		}

		// The background cleaner (not a lazy Get) must remove the expired
		// entry. Advancing the fake clock past one tick fires the cleaner;
		// Wait then blocks until its sweep has finished, so the assertion
		// below needs no polling and no deadline.
		time.Sleep(30 * time.Millisecond)
		synctest.Wait()

		cache.mu.Lock()
		n := len(cache.items)
		cache.mu.Unlock()
		if n != 0 {
			t.Fatalf("background cleaner left %d expired entries, want 0", n)
		}
	})
}

func TestMemoryCacheCloseIdempotent(t *testing.T) {
	cache := NewMemoryCache(10, time.Hour, 0)
	if err := cache.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := cache.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestFallbackCacheUnhealthyPrimary(t *testing.T) {
	ctx := context.Background()
	primary := &stubCache{healthy: false, data: map[string]string{"k": "from-primary"}}
	fallback := &stubCache{healthy: true, data: map[string]string{"k": "from-fallback"}}
	fc := NewFallbackCache(primary, fallback)

	// An unhealthy primary must be bypassed entirely, even when it has the key.
	r, err := fc.Get(ctx, "k")
	if err != nil || !r.Found || r.Data != "from-fallback" {
		t.Errorf("Get = %+v, %v; want fallback value", r, err)
	}

	// Set must skip the unhealthy primary and still write the fallback.
	if err := fc.Set(ctx, "new", "v", time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if primary.sets != 0 {
		t.Errorf("primary received %d writes while unhealthy, want 0", primary.sets)
	}
	if _, ok := fallback.data["new"]; !ok {
		t.Error("fallback missed the write")
	}

	if !fc.IsHealthy() {
		t.Error("FallbackCache must report healthy while the fallback is healthy")
	}
	if fc.IsPrimaryHealthy() {
		t.Error("IsPrimaryHealthy must reflect the unhealthy primary")
	}
}

// TestFallbackCacheRecoveryPurgesStaleDirtyKeys covers the scenario a stale
// primary entry, untouched during an outage, would otherwise shadow a
// newer value written to fallback for the rest of its original TTL once
// primary recovers.
// TestFallbackCacheMarksDirtyOnPrimarySetFailure covers the case where
// primary looked healthy when the write started, but the write itself
// failed (a transient error, discovered by this very call) — the key must
// still be tracked dirty, exactly as if primary had already been known
// unhealthy, since either way primary does not end up holding the value.
func TestFallbackCacheMarksDirtyOnPrimarySetFailure(t *testing.T) {
	ctx := context.Background()
	primary := &stubCache{healthy: true, setErr: errors.New("boom"), data: map[string]string{"k": "old"}}
	fallback := &stubCache{healthy: true}
	fc := NewFallbackCache(primary, fallback)

	if err := fc.Set(ctx, "k", "new", time.Minute); err == nil {
		t.Fatal("expected the primary error to propagate")
	}

	fc.dirtyMu.Lock()
	_, dirty := fc.dirty["k"]
	fc.dirtyMu.Unlock()
	if !dirty {
		t.Fatal("k must be tracked dirty when the primary write itself failed, not just when primary was already unhealthy")
	}

	// Once a later write to primary succeeds, the stale entry must actually
	// get purged — proving the dirty tracking does something, not just that
	// it's present.
	primary.setErr = nil
	r, err := fc.Get(ctx, "k")
	if err != nil || !r.Found || r.Data != "new" {
		t.Fatalf("Get after recovery = %+v, %v; want the newer fallback value once purged", r, err)
	}
	if len(primary.dels) != 1 || primary.dels[0] != "k" {
		t.Errorf("primary.dels = %v, want [\"k\"] purged", primary.dels)
	}
}

func TestFallbackCacheRecoveryPurgesStaleDirtyKeys(t *testing.T) {
	ctx := context.Background()
	// Primary starts down, already holding a pre-outage value for "k".
	primary := &stubCache{healthy: false, data: map[string]string{"k": "old"}}
	fallback := &stubCache{healthy: true}
	fc := NewFallbackCache(primary, fallback)

	// A write during the outage lands in fallback only; primary's stale
	// "old" is left untouched.
	if err := fc.Set(ctx, "k", "new", time.Minute); err != nil {
		t.Fatalf("Set during outage: %v", err)
	}
	if primary.sets != 0 {
		t.Errorf("primary should not be written to while unhealthy, got %d writes", primary.sets)
	}

	// Primary recovers, but its stale entry is still present and not yet
	// expired — without the fix this would shadow the newer fallback value.
	primary.healthy = true

	r, err := fc.Get(ctx, "k")
	if err != nil || !r.Found || r.Data != "new" {
		t.Fatalf("Get after recovery = %+v, %v; want the newer fallback value, not the stale primary one", r, err)
	}
	if want := []string{"k"}; len(primary.dels) != 1 || primary.dels[0] != want[0] {
		t.Errorf("primary.dels = %v, want exactly %v purged on recovery", primary.dels, want)
	}
}

// TestFallbackCacheFlushDirtyRetriesOnFailure verifies a failed purge leaves
// the key tracked as dirty so a later successful attempt still cleans it up,
// instead of silently giving up after one failure.
func TestFallbackCacheFlushDirtyRetriesOnFailure(t *testing.T) {
	ctx := context.Background()
	primary := &stubCache{healthy: false, data: map[string]string{"k": "old"}}
	fallback := &stubCache{healthy: true}
	fc := NewFallbackCache(primary, fallback)

	if err := fc.Set(ctx, "k", "new", time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	primary.healthy = true
	primary.delErr = errors.New("boom")
	if _, err := fc.Get(ctx, "k"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(primary.dels) != 1 {
		t.Fatalf("expected one attempted Del, got %d", len(primary.dels))
	}
	if r, _ := primary.Get(ctx, "k"); !r.Found {
		t.Fatal("a failed Del must not have actually deleted the key")
	}

	// A later successful flush must retry and finally purge it.
	primary.delErr = nil
	r, err := fc.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get (retry): %v", err)
	}
	if len(primary.dels) != 2 {
		t.Errorf("expected a second Del attempt, got %d calls", len(primary.dels))
	}
	if !r.Found || r.Data != "new" {
		t.Errorf("Get (retry) = %+v, want the fallback value once the stale primary entry is finally purged", r)
	}
}

// TestFallbackCacheDirtySetIsBounded verifies the dirty-key set stops
// growing past maxDirtyKeys during a long outage, rather than growing
// without bound.
func TestFallbackCacheDirtySetIsBounded(t *testing.T) {
	ctx := context.Background()
	primary := &stubCache{healthy: false}
	fallback := &stubCache{healthy: true}
	fc := NewFallbackCache(primary, fallback)

	for i := 0; i < maxDirtyKeys+5; i++ {
		if err := fc.Set(ctx, fmt.Sprintf("k%d", i), "v", time.Minute); err != nil {
			t.Fatalf("Set: %v", err)
		}
	}

	fc.dirtyMu.Lock()
	n := len(fc.dirty)
	fc.dirtyMu.Unlock()
	if n != maxDirtyKeys {
		t.Errorf("dirty set size = %d, want capped at %d", n, maxDirtyKeys)
	}
}

func TestFallbackCachePrimaryMissFallsThrough(t *testing.T) {
	ctx := context.Background()
	// Healthy but empty primary: entries written to memory during a Redis
	// outage must still be served after Redis recovers (documented behavior).
	primary := &stubCache{healthy: true}
	fallback := &stubCache{healthy: true, data: map[string]string{"k": "survived"}}
	fc := NewFallbackCache(primary, fallback)

	r, err := fc.Get(ctx, "k")
	if err != nil || !r.Found || r.Data != "survived" {
		t.Errorf("Get = %+v, %v; want fall-through to fallback on primary miss", r, err)
	}
}

func TestFallbackCacheSetPrimaryError(t *testing.T) {
	ctx := context.Background()
	wantErr := errors.New("primary write failed")
	primary := &stubCache{healthy: true, setErr: wantErr}
	fallback := &stubCache{healthy: true}
	fc := NewFallbackCache(primary, fallback)

	if err := fc.Set(ctx, "k", "v", time.Minute); !errors.Is(err, wantErr) {
		t.Errorf("Set error = %v, want primary error", err)
	}
	if _, ok := fallback.data["k"]; !ok {
		t.Error("fallback must be written even when the primary write fails")
	}
}

func TestFallbackCacheClose(t *testing.T) {
	primary := &stubCache{healthy: true}
	fallback := &stubCache{healthy: true}
	fc := NewFallbackCache(primary, fallback)

	if err := fc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if primary.closed != 1 || fallback.closed != 1 {
		t.Errorf("closed counts = %d/%d, want 1/1", primary.closed, fallback.closed)
	}
}
