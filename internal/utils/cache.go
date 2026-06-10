package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// CacheResult represents the result of a cache operation
type CacheResult struct {
	Data  string
	Found bool
}

// GetFromCache attempts to retrieve data from cache (uses unified cache manager)
func GetFromCache(ctx context.Context, cache Cache, key string) (CacheResult, error) {
	return cache.Get(ctx, key)
}

// SetToCache stores data in cache with expiration (uses unified cache manager)
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
