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

// GetFromCache attempts to retrieve data from Redis cache
func GetFromCache(ctx context.Context, redisClient *redis.Client, key string) (CacheResult, error) {
	cacheResult, err := redisClient.Get(ctx, key).Result()
	if err == nil {
		log.Printf("Serving cached result for resource with key: %s\n", key)
		return CacheResult{Data: cacheResult, Found: true}, nil
	} else if err == redis.Nil {
		// Cache miss - not an error
		return CacheResult{Found: false}, nil
	}
	// Actual error occurred
	return CacheResult{Found: false}, err
}

// SetToCache stores data in Redis cache with expiration
func SetToCache(ctx context.Context, redisClient *redis.Client, key string, data interface{}, expiration time.Duration) error {
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

// HandleCacheResponse writes cached data to HTTP response
func HandleCacheResponse(w http.ResponseWriter, data string, contentType string) {
	if contentType == "" {
		contentType = "application/json"
	}
	w.Header().Set("Content-Type", contentType)
	fmt.Fprint(w, data)
}
