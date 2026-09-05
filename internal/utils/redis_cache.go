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

// Get retrieves a value from Redis cache, along with its remaining TTL (read
// back via a pipelined TTL alongside the GET, so this costs no extra round
// trip) so callers can tell an entry about to expire from a freshly written
// one.
func (rc *RedisCache) Get(ctx context.Context, key string) (CacheResult, error) {
	if !rc.IsHealthy() {
		return CacheResult{Found: false}, nil
	}

	var getCmd *redis.StringCmd
	var ttlCmd *redis.DurationCmd
	_, _ = rc.client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		getCmd = pipe.Get(ctx, key)
		ttlCmd = pipe.TTL(ctx, key)
		return nil
	})
	// The pipeline's own aggregate error (discarded above) mirrors each
	// command's individual error when the whole pipeline fails (e.g. a
	// network error), so checking getCmd's own result covers both cases.

	cacheResult, err := getCmd.Result()
	switch err {
	case nil:
		slog.Debug("cache hit", "backend", "redis", "key", key)
		metrics.CacheRequestsTotal.WithLabelValues("redis", "hit").Inc()
		result := CacheResult{Data: cacheResult, Found: true}
		if ttl, ttlErr := ttlCmd.Result(); ttlErr == nil && ttl > 0 {
			result.ExpiresAt = time.Now().Add(ttl)
		}
		return result, nil
	case redis.Nil:
		metrics.CacheRequestsTotal.WithLabelValues("redis", "miss").Inc()
		return CacheResult{Found: false}, nil
	default:
		// A cancelled or expired caller context is not a Redis fault. Don't let
		// one client's abort mark the shared connection unhealthy for every
		// other in-flight request.
		if ctx.Err() != nil {
			return CacheResult{Found: false}, err
		}
		slog.Warn("Redis GET failed", "key", key, "err", err)
		metrics.CacheRequestsTotal.WithLabelValues("redis", "error").Inc()
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
		// As in Get: a cancelled/expired caller context must not be attributed
		// to Redis and flip the shared health flag.
		if ctx.Err() != nil {
			return err
		}
		slog.Warn("Redis SET failed", "key", key, "err", err)
		metrics.CacheRequestsTotal.WithLabelValues("redis", "error").Inc()
		rc.setHealthy(false)
		return err
	}

	return nil
}

// Del removes keys from Redis cache outright. Used by FallbackCache to purge
// stale entries left over from an outage; a no-op (not an error) when there
// is nothing to delete or the connection is currently unhealthy, matching
// Set's silent-skip behavior.
func (rc *RedisCache) Del(ctx context.Context, keys ...string) error {
	if len(keys) == 0 || !rc.IsHealthy() {
		return nil
	}

	if err := rc.client.Del(ctx, keys...).Err(); err != nil {
		if ctx.Err() != nil {
			return err
		}
		slog.Warn("Redis DEL failed", "keys", len(keys), "err", err)
		metrics.CacheRequestsTotal.WithLabelValues("redis", "error").Inc()
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
