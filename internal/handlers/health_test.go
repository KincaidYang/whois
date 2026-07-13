package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/utils"
)

// healthStubCache is a Cache with scripted health, standing in for the Redis
// primary inside a FallbackCache.
type healthStubCache struct {
	healthy bool
}

func (s *healthStubCache) Get(ctx context.Context, key string) (utils.CacheResult, error) {
	return utils.CacheResult{Found: false}, nil
}

func (s *healthStubCache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	return nil
}

func (s *healthStubCache) IsHealthy() bool { return s.healthy }

func saveCacheGlobals(t *testing.T) {
	t.Helper()
	oldManager, oldRequire := config.CacheManager, config.RequireRedis
	t.Cleanup(func() {
		config.CacheManager, config.RequireRedis = oldManager, oldRequire
	})
}

func decodeHealth(t *testing.T, w *httptest.ResponseRecorder) HealthStatus {
	t.Helper()
	var status HealthStatus
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("response is not JSON: %v (%q)", err, w.Body.String())
	}
	return status
}

func TestGetCacheCheckNotInitialized(t *testing.T) {
	saveCacheGlobals(t)
	config.CacheManager = nil

	check, ok := getCacheCheck()
	if ok || check.Status != "fail" {
		t.Errorf("uninitialized cache: check = %+v ok=%v, want fail/false", check, ok)
	}

	// /ready must report unavailable before the cache manager exists.
	config.RequireRedis = false
	w := httptest.NewRecorder()
	HandleReady(w, httptest.NewRequest("GET", "/ready", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("/ready = %d, want 503 with no cache manager", w.Code)
	}
}

func TestGetCacheCheckMemoryOnly(t *testing.T) {
	saveCacheGlobals(t)
	mc := utils.NewMemoryCache(4, time.Minute)
	t.Cleanup(func() { _ = mc.Close() })
	config.CacheManager = mc

	check, ok := getCacheCheck()
	if !ok || check.Status != "ok" || check.Message != "memory" {
		t.Errorf("memory-only: check = %+v ok=%v, want ok/memory", check, ok)
	}
	if isRedisHealthy() {
		t.Error("memory-only mode must never report Redis as healthy")
	}
}

func TestGetCacheCheckRedisHealthy(t *testing.T) {
	saveCacheGlobals(t)
	mc := utils.NewMemoryCache(4, time.Minute)
	t.Cleanup(func() { _ = mc.Close() })
	config.CacheManager = utils.NewFallbackCache(&healthStubCache{healthy: true}, mc)

	check, ok := getCacheCheck()
	if !ok || check.Message != "redis" {
		t.Errorf("healthy redis: check = %+v ok=%v, want ok/redis", check, ok)
	}

	w := httptest.NewRecorder()
	HandleHealth(w, httptest.NewRequest("GET", "/health", nil))
	if w.Code != http.StatusOK {
		t.Errorf("/health = %d, want 200", w.Code)
	}
	if status := decodeHealth(t, w); status.Checks["cache"].Message != "redis" {
		t.Errorf("/health cache check = %+v, want redis", status.Checks["cache"])
	}
}

func TestHandleReadyRequireRedisUnavailable(t *testing.T) {
	saveCacheGlobals(t)
	mc := utils.NewMemoryCache(4, time.Minute)
	t.Cleanup(func() { _ = mc.Close() })
	config.CacheManager = utils.NewFallbackCache(&healthStubCache{healthy: false}, mc)
	config.RequireRedis = true

	w := httptest.NewRecorder()
	HandleReady(w, httptest.NewRequest("GET", "/ready", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("/ready = %d, want 503 when required Redis is down", w.Code)
	}
	status := decodeHealth(t, w)
	if status.Status != "unavailable" || status.Checks["cache"].Status != "fail" {
		t.Errorf("/ready body = %+v, want unavailable with failed cache check", status)
	}
}

func TestGetCapacityCheckAtLimit(t *testing.T) {
	oldLimiter, oldLimit := config.ConcurrencyLimiter, config.RateLimit
	t.Cleanup(func() {
		config.ConcurrencyLimiter, config.RateLimit = oldLimiter, oldLimit
	})

	config.RateLimit = 1
	config.ConcurrencyLimiter = make(chan struct{}, 1)

	if check := getCapacityCheck(); check.Status != "ok" {
		t.Errorf("idle: check = %+v, want ok", check)
	}

	config.ConcurrencyLimiter <- struct{}{}
	if check := getCapacityCheck(); check.Status != "warning" {
		t.Errorf("at limit: check = %+v, want warning", check)
	}
}

func TestHandleInfoIncludesBuildInfo(t *testing.T) {
	oldBuild, oldCommit := config.BuildTime, config.GitCommit
	t.Cleanup(func() { config.BuildTime, config.GitCommit = oldBuild, oldCommit })

	config.BuildTime = "2026-01-02T03:04:05Z"
	config.GitCommit = "abc1234"

	w := httptest.NewRecorder()
	HandleInfo(w, httptest.NewRequest("GET", "/info", nil))

	var info RuntimeInfo
	if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if info.BuildTime != "2026-01-02T03:04:05Z" || info.GitCommit != "abc1234" {
		t.Errorf("info = %+v, want stamped build time and commit", info)
	}
}
