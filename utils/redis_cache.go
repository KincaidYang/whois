package utils

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCache implements Cache interface using Redis
type RedisCache struct {
	client        *redis.Client
	healthy       bool
	healthChecked bool // Whether we've done the initial health check
	mu            sync.RWMutex
}

// NewRedisCache creates a new Redis cache instance
func NewRedisCache(client *redis.Client) *RedisCache {
	rc := &RedisCache{
		client:        client,
		healthy:       false,
		healthChecked: false,
	}

	// Check initial health
	rc.checkHealth(true)

	// Start background health checker
	go rc.startHealthChecker()

	return rc
}

// Get retrieves a value from Redis cache
func (rc *RedisCache) Get(ctx context.Context, key string) (CacheResult, error) {
	if !rc.IsHealthy() {
		return CacheResult{Found: false}, nil
	}

	cacheResult, err := rc.client.Get(ctx, key).Result()
	switch {
	case err == nil:
		log.Printf("Serving cached result from Redis for key: %s\n", key)
		return CacheResult{Data: cacheResult, Found: true}, nil
	case err == redis.Nil:
		// Cache miss - not an error
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
		// Log only on initial check or when state changes from healthy to unhealthy
		if isInitial {
			log.Printf("⚠ Redis unavailable: %v\n", err)
		} else if wasHealthy {
			log.Printf("⚠ Redis connection lost: %v\n", err)
		}
		// Don't log repeated failures during background checks
	} else {
		rc.setHealthy(true)
		// Log when connection is restored (not on initial success)
		if !isInitial && !wasHealthy {
			log.Println("✓ Redis connection restored")
		}
	}

	rc.mu.Lock()
	rc.healthChecked = true
	rc.mu.Unlock()
}

// startHealthChecker runs periodic health checks
func (rc *RedisCache) startHealthChecker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		rc.checkHealth(false)
	}
}
