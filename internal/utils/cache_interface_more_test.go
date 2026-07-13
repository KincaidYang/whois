package utils

import (
	"context"
	"errors"
	"testing"
	"time"
)

// stubCache is a Cache whose health, contents and errors are scripted, so
// FallbackCache routing can be asserted without a real backend.
type stubCache struct {
	healthy bool
	data    map[string]string
	setErr  error
	sets    int
	closed  int
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

func (s *stubCache) Close() error {
	s.closed++
	return nil
}

func TestMemoryCacheLRUEviction(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryCache(2, time.Hour)
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

func TestMemoryCacheCleanExpired(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryCache(10, time.Hour) // cleaner ticker never fires in-test
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
}

func TestMemoryCacheCleanerLoop(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryCache(10, 20*time.Millisecond)
	defer func() { _ = cache.Close() }()

	if err := cache.Set(ctx, "dead", "v", time.Millisecond); err != nil {
		t.Fatal(err)
	}

	// The background cleaner (not a lazy Get) must remove the expired entry.
	deadline := time.Now().Add(2 * time.Second)
	for {
		cache.mu.Lock()
		n := len(cache.items)
		cache.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background cleaner did not remove the expired entry in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestMemoryCacheCloseIdempotent(t *testing.T) {
	cache := NewMemoryCache(10, time.Hour)
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
