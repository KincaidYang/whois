package utils

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/KincaidYang/whois/internal/metrics"
	"github.com/redis/go-redis/v9"
)

// RedisCache implements Cache interface using Redis
type RedisCache struct {
	client    *redis.Client
	healthy   bool
	mu        sync.RWMutex
	done      chan struct{}
	closeOnce sync.Once
}

// NewRedisCache creates a new Redis cache instance
func NewRedisCache(client *redis.Client) *RedisCache {
	rc := &RedisCache{
		client:  client,
		healthy: false,
		done:    make(chan struct{}),
	}

	// Check initial health
	rc.checkHealth(true)

	// Start background health checker
	go rc.startHealthChecker()

	return rc
}

// Close stops the background health checker goroutine. It does not close the
// underlying Redis client, which is owned by the caller. Safe to call multiple times.
func (rc *RedisCache) Close() error {
	rc.closeOnce.Do(func() { close(rc.done) })
	return nil
}

// Get retrieves a value from Redis cache
func (rc *RedisCache) Get(ctx context.Context, key string) (CacheResult, error) {
	if !rc.IsHealthy() {
		return CacheResult{Found: false}, nil
	}

	cacheResult, err := rc.client.Get(ctx, key).Result()
	switch err {
	case nil:
		slog.Debug("cache hit", "backend", "redis", "key", key)
		metrics.CacheRequestsTotal.WithLabelValues("redis", "hit").Inc()
		return CacheResult{Data: cacheResult, Found: true}, nil
	case redis.Nil:
		metrics.CacheRequestsTotal.WithLabelValues("redis", "miss").Inc()
		return CacheResult{Found: false}, nil
	default:
		// Redis error occurred, mark as unhealthy
		rc.setHealthy(false)
		return CacheResult{Found: false}, err
	}
}

// Set stores a value in Redis cache
func (rc *RedisCache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	if !rc.IsHealthy() {
		return nil // Silently skip if unhealthy
	}

	err := rc.client.Set(ctx, key, value, expiration).Err()
	if err != nil {
		rc.setHealthy(false)
		return err
	}

	return nil
}

// IsHealthy returns the health status of Redis connection
func (rc *RedisCache) IsHealthy() bool {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.healthy
}

// setHealthy safely sets the healthy status
func (rc *RedisCache) setHealthy(healthy bool) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.healthy = healthy
}

// checkHealth performs a health check on Redis
func (rc *RedisCache) checkHealth(isInitial bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	wasHealthy := rc.IsHealthy()
	_, err := rc.client.Ping(ctx).Result()

	if err != nil {
		rc.setHealthy(false)
		if isInitial {
			slog.Warn("Redis unavailable", "err", err)
		} else if wasHealthy {
			slog.Warn("Redis connection lost", "err", err)
		}
	} else {
		rc.setHealthy(true)
		if !isInitial && !wasHealthy {
			slog.Info("Redis connection restored")
		}
	}

}

// startHealthChecker runs periodic health checks until Close is called
func (rc *RedisCache) startHealthChecker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rc.checkHealth(false)
		case <-rc.done:
			return
		}
	}
}
