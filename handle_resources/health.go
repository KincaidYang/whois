package handle_resources

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/KincaidYang/whois/config"
	"github.com/KincaidYang/whois/utils"
)

// startTime records the server start time for uptime calculation
var startTime = time.Now()

// HealthStatus represents the overall health status
type HealthStatus struct {
	Status    string           `json:"status"`
	Timestamp string           `json:"timestamp"`
	Uptime    string           `json:"uptime,omitempty"`
	Checks    map[string]Check `json:"checks"`
}

// Check represents a single health check result
type Check struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// isRedisHealthy checks if the primary cache (Redis) is healthy
func isRedisHealthy() bool {
	if config.CacheManager == nil {
		return false
	}
	if fc, ok := config.CacheManager.(*utils.FallbackCache); ok {
		return fc.IsPrimaryHealthy()
	}
	return config.CacheManager.IsHealthy()
}

// getCacheCheck returns the cache health check result
func getCacheCheck() (Check, bool) {
	if config.CacheManager == nil {
		return Check{Status: "fail", Message: "not initialized"}, false
	}
	if isRedisHealthy() {
		return Check{Status: "ok", Message: "redis"}, true
	}
	return Check{Status: "ok", Message: "memory"}, true
}

// getCapacityCheck returns the capacity health check result
func getCapacityCheck() Check {
	currentLoad := len(config.ConcurrencyLimiter)
	if currentLoad >= config.RateLimit {
		return Check{Status: "warning", Message: fmt.Sprintf("at limit (%d/%d)", currentLoad, config.RateLimit)}
	}
	return Check{Status: "ok", Message: fmt.Sprintf("%d/%d", currentLoad, config.RateLimit)}
}

// HandleHealth handles the /health endpoint
// Returns basic health status - always returns 200 if the server is running
func HandleHealth(w http.ResponseWriter, r *http.Request) {
	cacheCheck, _ := getCacheCheck()

	status := HealthStatus{
		Status:    "ok",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Uptime:    time.Since(startTime).Round(time.Second).String(),
		Checks: map[string]Check{
			"cache": cacheCheck,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
}

// HandleReady handles the /ready endpoint
// Returns 200 if the service is ready to accept requests
// Returns 503 if dependencies are not available and requireRedis is true
func HandleReady(w http.ResponseWriter, r *http.Request) {
	httpStatus := http.StatusOK
	overallStatus := "ok"

	cacheCheck, cacheOk := getCacheCheck()

	// If Redis is required but unavailable, mark as unavailable
	if config.RequireRedis && !isRedisHealthy() {
		overallStatus = "unavailable"
		cacheCheck = Check{Status: "fail", Message: "redis required but unavailable"}
		httpStatus = http.StatusServiceUnavailable
	} else if !cacheOk {
		overallStatus = "unavailable"
		httpStatus = http.StatusServiceUnavailable
	}

	status := HealthStatus{
		Status:    overallStatus,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Uptime:    time.Since(startTime).Round(time.Second).String(),
		Checks: map[string]Check{
			"cache":    cacheCheck,
			"capacity": getCapacityCheck(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(status)
}

// RuntimeInfo represents runtime information
type RuntimeInfo struct {
	Version      string `json:"version"`
	BuildTime    string `json:"buildTime,omitempty"`
	GitCommit    string `json:"gitCommit,omitempty"`
	GoVersion    string `json:"goVersion"`
	Uptime       string `json:"uptime"`
	NumGoroutine int    `json:"numGoroutine"`
	NumCPU       int    `json:"numCPU"`
}

// HandleInfo handles the /info endpoint (optional, for debugging)
func HandleInfo(w http.ResponseWriter, r *http.Request) {
	info := RuntimeInfo{
		Version:      config.Version,
		GoVersion:    runtime.Version(),
		Uptime:       time.Since(startTime).Round(time.Second).String(),
		NumGoroutine: runtime.NumGoroutine(),
		NumCPU:       runtime.NumCPU(),
	}

	// Only include build info if available
	if config.BuildTime != "unknown" {
		info.BuildTime = config.BuildTime
	}
	if config.GitCommit != "unknown" {
		info.GitCommit = config.GitCommit
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}
