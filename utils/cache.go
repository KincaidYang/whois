package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

// CacheResult represents the result of a cache operation
type CacheResult struct {
	Data  string
	Found bool
}

// GetFromCache attempts to retrieve data from cache (uses unified cache manager)
// This function is kept for backward compatibility but now uses the Cache interface
func GetFromCache(ctx context.Context, cache Cache, key string) (CacheResult, error) {
	return cache.Get(ctx, key)
}

// SetToCache stores data in cache with expiration (uses unified cache manager)
// This function is kept for backward compatibility but now uses the Cache interface
func SetToCache(ctx context.Context, cache Cache, key string, data interface{}, expiration time.Duration) error {
	var dataStr string

	switch v := data.(type) {
	case string:
		dataStr = v
	default:
		// Marshal to JSON for non-string data
		resultBytes, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to marshal data for caching: %w", err)
		}
		dataStr = string(resultBytes)
	}

	return cache.Set(ctx, key, dataStr, expiration)
}

// HandleCacheResponse writes cached data to HTTP response
func HandleCacheResponse(w http.ResponseWriter, data string, contentType string) {
	if contentType == "" {
		contentType = "application/json"
	}
	w.Header().Set("Content-Type", contentType)
	fmt.Fprint(w, data)
}

// Legacy functions for direct Redis access (deprecated, kept for compatibility)

// GetFromCacheRedis is deprecated, use GetFromCache with Cache interface instead
func GetFromCacheRedis(ctx context.Context, redisClient *redis.Client, key string) (CacheResult, error) {
	cacheResult, err := redisClient.Get(ctx, key).Result()
	switch {
	case err == nil:
		log.Printf("Serving cached result for resource with key: %s\n", key)
		return CacheResult{Data: cacheResult, Found: true}, nil
	case err == redis.Nil:
		// Cache miss - not an error
		return CacheResult{Found: false}, nil
	default:
		// Actual error occurred
		return CacheResult{Found: false}, err
	}
}

// SetToCacheRedis is deprecated, use SetToCache with Cache interface instead
func SetToCacheRedis(ctx context.Context, redisClient *redis.Client, key string, data interface{}, expiration time.Duration) error {
	var dataStr string

	switch v := data.(type) {
	case string:
		dataStr = v
	default:
		// Marshal to JSON for non-string data
		resultBytes, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to marshal data for caching: %w", err)
		}
		dataStr = string(resultBytes)
	}

	err := redisClient.Set(ctx, key, dataStr, expiration).Err()
	if err != nil {
		log.Printf("Failed to cache result for key: %s, error: %v\n", key, err)
		return err
	}

	return nil
}
