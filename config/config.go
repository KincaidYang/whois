package config

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KincaidYang/whois/utils"
	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v3"
)

// discardLogger is a logger that discards all log messages
type discardLogger struct{}

func (l *discardLogger) Printf(ctx context.Context, format string, v ...interface{}) {
	// Discard all log messages
}

var (
	// Version information - read from build info (Go 1.18+)
	Version   string
	BuildTime string
	GitCommit string

	// redisClient is the Redis client
	RedisClient *redis.Client
	// CacheManager is the unified cache interface with fallback support
	CacheManager utils.Cache
	// CacheExpiration is the cache duration
	CacheExpiration time.Duration
	// HttpClient is used to set the timeout for rdapQuery
	HttpClient = &http.Client{
		Timeout: 10 * time.Second,
	}
	// Wg is used to wait for all goroutines to finish
	Wg sync.WaitGroup
	// Port is used to set the port the server listens on
	Port int
	// RateLimit is used to set the number of concurrent requests
	RateLimit          int
	ConcurrencyLimiter chan struct{}
	// ProxyServer is the proxy server
	ProxyServer string
	// ProxyUsername is the username for the proxy server
	ProxyUsername string
	// ProxyPassword is the password for the proxy server
	ProxyPassword string
	// ProxySuffixes is the list of TLDs that use a proxy server
	ProxySuffixes []string
	// Cache configuration
	RequireRedis        bool
	MemoryMaxSize       int
	MemoryCleanInterval time.Duration
)

func init() {
	// Initialize version info from build info (Go 1.18+)
	initVersionInfo()

	var config Config

	// Load configuration from file
	loadConfigFromFile(&config)

	// Override configuration with environment variables if they exist
	overrideConfigWithEnv(&config)

	// Apply default values for cache configuration (backward compatibility)
	applyDefaultCacheConfig(&config)

	// Initialize the Redis client with custom options
	options := &redis.Options{
		Addr:            config.Redis.Addr,
		Password:        config.Redis.Password,
		DB:              config.Redis.DB,
		PoolSize:        10,
		MinIdleConns:    0,
		MaxRetries:      1,
		MinRetryBackoff: 8 * time.Millisecond,
		MaxRetryBackoff: 512 * time.Millisecond,
		DialTimeout:     2 * time.Second,
		ReadTimeout:     2 * time.Second,
		WriteTimeout:    2 * time.Second,
		PoolTimeout:     2 * time.Second,
	}

	RedisClient = redis.NewClient(options)

	// Suppress Redis client's internal error logging by setting a discard logger
	// The client will still work, but won't spam logs on connection failures
	redis.SetLogger(&discardLogger{})

	// Set the cache expiration time
	CacheExpiration = time.Duration(config.CacheExpiration) * time.Second

	// Set cache configuration
	RequireRedis = config.Cache.RequireRedis
	MemoryMaxSize = config.Cache.MemoryMaxSize
	MemoryCleanInterval = time.Duration(config.Cache.MemoryCleanInterval) * time.Second

	// Initialize cache manager with fallback
	initializeCacheManager()

	// Set the port the server listens on
	Port = config.Port

	// Set the number of concurrent requests
	RateLimit = config.RateLimit
	ConcurrencyLimiter = make(chan struct{}, RateLimit)

	// Set the proxy server
	ProxyServer = config.ProxyServer
	ProxyUsername = config.ProxyUsername
	ProxyPassword = config.ProxyPassword
	ProxySuffixes = config.ProxySuffixes
}

// applyDefaultCacheConfig sets default values for cache configuration if not specified
func applyDefaultCacheConfig(config *Config) {
	// RequireRedis defaults to false (allow fallback to memory) - no action needed as bool defaults to false

	// Default: 10000 entries max in memory cache
	if config.Cache.MemoryMaxSize == 0 {
		config.Cache.MemoryMaxSize = 10000
	}

	// Default: clean every 5 minutes (300 seconds)
	if config.Cache.MemoryCleanInterval == 0 {
		config.Cache.MemoryCleanInterval = 300
	}
}

// initializeCacheManager sets up the cache with Redis primary and memory fallback
func initializeCacheManager() {
	// Create Redis cache
	redisCache := utils.NewRedisCache(RedisClient)

	// Create memory cache as fallback
	memoryCache := utils.NewMemoryCache(MemoryMaxSize, MemoryCleanInterval)

	// Create fallback cache that tries Redis first, then memory
	CacheManager = utils.NewFallbackCache(redisCache, memoryCache)

	// Log cache configuration
	if redisCache.IsHealthy() {
		log.Println("✓ Redis cache initialized successfully")
	} else {
		log.Println("⚠ Redis unavailable, using memory cache as fallback")
		if RequireRedis {
			log.Fatal("Redis is required but unavailable. Set cache.requireRedis to false to allow fallback.")
		}
	}

	log.Printf("Cache configuration: Max memory entries=%d, Clean interval=%v\n",
		MemoryMaxSize, MemoryCleanInterval)
}

func loadConfigFromFile(config *Config) {
	configFile, err := os.Open("config.yaml")
	if err != nil {
		configFile, err = os.Open("config.json")
		if err != nil {
			log.Fatalf("Failed to open configuration file: %v", err)
		}
	}
	defer configFile.Close()

	fileExt := strings.ToLower(filepath.Ext(configFile.Name()))
	switch fileExt {
	case ".yaml", ".yml":
		decoder := yaml.NewDecoder(configFile)
		err = decoder.Decode(config)
		if err != nil {
			log.Fatalf("Failed to decode YAML from configuration file: %v", err)
		}
	case ".json":
		decoder := json.NewDecoder(configFile)
		err = decoder.Decode(config)
		if err != nil {
			log.Fatalf("Failed to decode JSON from configuration file: %v", err)
		}
	default:
		log.Fatalf("Unsupported configuration file format: %s", fileExt)
	}
}

func overrideConfigWithEnv(config *Config) {
	// Override Redis configuration
	if redisAddr := os.Getenv("WHOIS_REDIS_ADDR"); redisAddr != "" {
		config.Redis.Addr = redisAddr
	}
	if redisPassword := os.Getenv("WHOIS_REDIS_PASSWORD"); redisPassword != "" {
		config.Redis.Password = redisPassword
	}
	if redisDB := os.Getenv("WHOIS_REDIS_DB"); redisDB != "" {
		if dbInt, err := strconv.Atoi(redisDB); err == nil {
			config.Redis.DB = dbInt
		}
	}

	// Override general configuration
	if cacheExpiration := os.Getenv("WHOIS_CACHE_EXPIRATION"); cacheExpiration != "" {
		if cacheInt, err := strconv.Atoi(cacheExpiration); err == nil {
			config.CacheExpiration = cacheInt
		}
	}

	// Override cache configuration
	if requireRedis := os.Getenv("WHOIS_REQUIRE_REDIS"); requireRedis != "" {
		config.Cache.RequireRedis = requireRedis == "true" || requireRedis == "1"
	}
	if memoryMaxSize := os.Getenv("WHOIS_MEMORY_MAX_SIZE"); memoryMaxSize != "" {
		if maxSize, err := strconv.Atoi(memoryMaxSize); err == nil {
			config.Cache.MemoryMaxSize = maxSize
		}
	}
	if memoryCleanInterval := os.Getenv("WHOIS_MEMORY_CLEAN_INTERVAL"); memoryCleanInterval != "" {
		if interval, err := strconv.Atoi(memoryCleanInterval); err == nil {
			config.Cache.MemoryCleanInterval = interval
		}
	}

	if port := os.Getenv("WHOIS_PORT"); port != "" {
		if portInt, err := strconv.Atoi(port); err == nil {
			config.Port = portInt
		}
	}
	if rateLimit := os.Getenv("WHOIS_RATE_LIMIT"); rateLimit != "" {
		if rateInt, err := strconv.Atoi(rateLimit); err == nil {
			config.RateLimit = rateInt
		}
	}
	if proxyServer := os.Getenv("WHOIS_PROXY_SERVER"); proxyServer != "" {
		config.ProxyServer = proxyServer
	}
	if proxyUsername := os.Getenv("WHOIS_PROXY_USERNAME"); proxyUsername != "" {
		config.ProxyUsername = proxyUsername
	}
	if proxyPassword := os.Getenv("WHOIS_PROXY_PASSWORD"); proxyPassword != "" {
		config.ProxyPassword = proxyPassword
	}
	if proxySuffixes := os.Getenv("WHOIS_PROXY_SUFFIXES"); proxySuffixes != "" {
		config.ProxySuffixes = strings.Split(proxySuffixes, ",")
	}
}

// initVersionInfo reads version information from Go build info
// This works automatically with `go build` (Go 1.18+)
func initVersionInfo() {
	Version = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	// Get module version
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		Version = info.Main.Version
	}

	// Get VCS info from build settings
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			if len(setting.Value) >= 7 {
				GitCommit = setting.Value[:7] // short commit hash
			} else {
				GitCommit = setting.Value
			}
		case "vcs.time":
			BuildTime = setting.Value
		case "vcs.modified":
			if setting.Value == "true" {
				GitCommit += "-dirty"
			}
		}
	}
}
