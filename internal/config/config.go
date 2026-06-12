package config

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KincaidYang/whois/internal/utils"
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
	// HttpClient is used to set the timeout for rdapQuery. RDAP queries hit
	// the same small set of registry servers repeatedly, so the transport
	// keeps idle connections around for reuse instead of redialing.
	HttpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
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
	// NegativeCacheExpiration is how long not-found/denied results are cached.
	NegativeCacheExpiration time.Duration
	// BootstrapInterval is how often to refresh RDAP server lists from IANA.
	BootstrapInterval time.Duration
	// MCPLocalhostProtection enables DNS-rebinding protection on the /mcp
	// endpoint. Defaults to false for reverse proxy deployments.
	MCPLocalhostProtection bool
	// AuthClients is the list of accepted API clients (key + display name +
	// optional rate limit). Empty leaves the service open; non-empty enables
	// authentication on every endpoint except /health and /ready.
	AuthClients []AuthClient
)

// AuthClient is the runtime form of one auth.keys entry: the secret itself
// plus the name used to label the caller in logs and metrics.
type AuthClient struct {
	Key  string
	Name string
	// RateLimit is the per-key budget in requests per minute; 0 = unlimited.
	RateLimit int
}

// RequestTimeout bounds how long a single query may take, so a slow upstream
// WHOIS/RDAP server cannot hold a concurrency slot indefinitely. It must stay
// below the HTTP server's WriteTimeout (20s) so the handler returns first, and
// above the per-upstream dial/read timeout (10s) to allow one full upstream
// attempt. Shared by the HTTP handler and the MCP tool handler.
const RequestTimeout = 15 * time.Second

// initLogger sets up the global slog JSON handler with the given level string.
// Accepted values: "debug", "info", "warn", "error" (case-insensitive).
// Defaults to Info for any unrecognised value.
func initLogger(levelStr string) {
	var level slog.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(utils.NewContextHandler(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))))
}

var loadOnce sync.Once

// Load reads the configuration file, applies environment overrides and
// initializes all package state (logger, Redis client, cache manager).
// It must be called once at startup before any other package is used;
// repeated calls are no-ops. On configuration errors it logs and exits.
func Load() {
	loadOnce.Do(load)
}

func load() {
	// Initialize version info from build info (Go 1.18+)
	initVersionInfo()

	// Load configuration from file
	data, ext, err := readConfigFile()
	if err != nil {
		slog.Error("failed to open configuration file", "err", err)
		os.Exit(1)
	}
	config, err := parseConfig(data, ext)
	if err != nil {
		slog.Error("invalid configuration", "err", err)
		os.Exit(1)
	}

	// Override configuration with environment variables if they exist
	overrideConfigWithEnv(&config)

	// Set up structured logger as early as possible so all subsequent
	// init messages use the configured level and JSON format.
	initLogger(config.Log.Level)

	// Apply default values for anything left unset
	applyDefaults(&config)

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
	if config.Redis.TLS {
		options.TLSConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: config.Redis.TLSSkipVerify,
		}
	}

	RedisClient = redis.NewClient(options)

	// Suppress Redis client's internal error logging by setting a discard logger
	// The client will still work, but won't spam logs on connection failures
	redis.SetLogger(&discardLogger{})

	// Set the cache expiration time
	CacheExpiration = time.Duration(config.Cache.Expiration) * time.Second

	// Set cache configuration
	RequireRedis = config.Cache.RequireRedis
	MemoryMaxSize = config.Cache.MemoryMaxSize
	MemoryCleanInterval = time.Duration(config.Cache.MemoryCleanInterval) * time.Second
	NegativeCacheExpiration = time.Duration(config.Cache.NegativeExpiration) * time.Second

	// Initialize cache manager with fallback
	initializeCacheManager()

	// Set the port the server listens on
	Port = config.Server.Port

	// Set the number of concurrent requests
	RateLimit = config.Server.RateLimit
	ConcurrencyLimiter = make(chan struct{}, RateLimit)

	// Set the proxy server
	ProxyServer = config.Proxy.Server
	ProxyUsername = config.Proxy.Username
	ProxyPassword = config.Proxy.Password
	ProxySuffixes = config.Proxy.Suffixes

	// Set the bootstrap interval
	BootstrapInterval = time.Duration(config.Bootstrap.Interval) * time.Second

	// Set MCP endpoint options
	MCPLocalhostProtection = config.MCP.LocalhostProtection

	// Set API authentication clients
	authClients, err := normalizeAuthClients(config.Auth.Keys)
	if err != nil {
		slog.Error("invalid configuration", "err", err)
		os.Exit(1)
	}
	AuthClients = authClients
	if len(AuthClients) > 0 {
		names := make([]string, len(AuthClients))
		for i, c := range AuthClients {
			names[i] = c.Name
		}
		slog.Info("API key authentication enabled", "clients", names)
	}
}

// normalizeAuthClients turns the configured auth.keys entries into runtime
// clients. Keys are trimmed and must be non-empty: a request with no
// credentials presents the empty key, so an accidental "" in auth.keys would
// turn authentication on while accepting every request. Names default to
// key1, key2, … by position; they end up in logs and Prometheus label values,
// so they are held to the same charset/length rule as request IDs. Duplicate
// keys or names are rejected — duplicate keys would make the matched client
// ambiguous, duplicate names would silently merge two callers' metrics.
func normalizeAuthClients(specs []AuthKeySpec) ([]AuthClient, error) {
	clients := make([]AuthClient, len(specs))
	seenKeys := make(map[string]bool, len(specs))
	seenNames := make(map[string]bool, len(specs))
	for i, spec := range specs {
		key := strings.TrimSpace(spec.Key)
		if key == "" {
			return nil, fmt.Errorf("auth.keys must not contain empty keys")
		}
		if seenKeys[key] {
			return nil, fmt.Errorf("auth.keys entry %d: duplicate key", i+1)
		}
		seenKeys[key] = true

		name := strings.TrimSpace(spec.Name)
		if name == "" {
			name = fmt.Sprintf("key%d", i+1)
		} else if !utils.IsValidRequestID(name) {
			return nil, fmt.Errorf("auth.keys entry %d: name %q must be 1-64 characters of [A-Za-z0-9._-]", i+1, spec.Name)
		}
		if seenNames[name] {
			return nil, fmt.Errorf("auth.keys entry %d: duplicate name %q", i+1, name)
		}
		seenNames[name] = true

		if spec.RateLimit < 0 {
			return nil, fmt.Errorf("auth.keys entry %d (%s): rateLimit must not be negative", i+1, name)
		}

		clients[i] = AuthClient{Key: key, Name: name, RateLimit: spec.RateLimit}
	}
	return clients, nil
}

// applyDefaults sets default values for configuration left unset
func applyDefaults(config *Config) {
	// Default: cache successful results for one hour
	if config.Cache.Expiration == 0 {
		config.Cache.Expiration = 3600
	}

	// Default: 10000 entries max in memory cache
	if config.Cache.MemoryMaxSize == 0 {
		config.Cache.MemoryMaxSize = 10000
	}

	// Default: clean every 5 minutes (300 seconds)
	if config.Cache.MemoryCleanInterval == 0 {
		config.Cache.MemoryCleanInterval = 300
	}

	// Default: cache not-found/denied results for 60 seconds.
	// A negative value disables negative caching; only 0 (unset) gets the default.
	if config.Cache.NegativeExpiration == 0 {
		config.Cache.NegativeExpiration = 60
	}

	// Default port: 8043
	if config.Server.Port == 0 {
		config.Server.Port = 8043
	}

	// Default rate limit: 100 concurrent requests
	if config.Server.RateLimit == 0 {
		config.Server.RateLimit = 100
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
		slog.Info("Redis cache initialized")
	} else {
		slog.Warn("Redis unavailable, falling back to memory cache")
		if RequireRedis {
			slog.Error("Redis is required but unavailable; set cache.requireRedis to false to allow fallback")
			os.Exit(1)
		}
	}

	slog.Info("cache configuration", "memory_max_entries", MemoryMaxSize, "clean_interval", MemoryCleanInterval)
}

// readConfigFile reads config.yaml (or config.json) and returns the raw bytes
// together with the file extension that selects the parser.
func readConfigFile() ([]byte, string, error) {
	for _, name := range []string{"config.yaml", "config.yml", "config.json"} {
		data, err := os.ReadFile(name)
		if err == nil {
			return data, strings.ToLower(filepath.Ext(name)), nil
		}
		if !os.IsNotExist(err) {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("no config.yaml or config.json found in the working directory")
}

// legacyKeys maps configuration keys from the pre-v0.9 layout (lowercased)
// to their new dotted location, used to build migration error messages.
var legacyKeys = map[string]string{
	// old top-level keys, now grouped
	"cacheexpiration":   "cache.expiration",
	"port":              "server.port",
	"ratelimit":         "server.rateLimit",
	"proxyserver":       "proxy.server",
	"proxyusername":     "proxy.username",
	"proxypassword":     "proxy.password",
	"proxysuffixes":     "proxy.suffixes",
	"loglevel":          "log.level",
	"bootstrapinterval": "bootstrap.interval",
	// old nested keys whose spelling changed (the old YAML tags were
	// all-lowercase; the new ones are camelCase)
	"redis.tlsskipverify":           "redis.tlsSkipVerify",
	"cache.requireredis":            "cache.requireRedis",
	"cache.memorymaxsize":           "cache.memoryMaxSize",
	"cache.memorycleaninterval":     "cache.memoryCleanInterval",
	"cache.negativecacheexpiration": "cache.negativeExpiration",
	"mcp.localhostprotection":       "mcp.localhostProtection",
}

// groupKeys are the only keys allowed at the top level of the configuration.
var groupKeys = map[string]bool{
	"server": true, "log": true, "cache": true, "redis": true,
	"proxy": true, "bootstrap": true, "mcp": true, "auth": true,
}

// detectLegacyKeys returns an error describing every pre-v0.9 key found in
// the raw configuration, so users get one complete migration list instead of
// a bare "unknown field" decode error.
func detectLegacyKeys(raw map[string]interface{}) error {
	var found []string
	appendLegacy := func(key string) {
		if newKey, ok := legacyKeys[strings.ToLower(key)]; ok {
			found = append(found, fmt.Sprintf("%q is now %q", key, newKey))
		}
	}
	for key, value := range raw {
		if !groupKeys[strings.ToLower(key)] {
			appendLegacy(key)
			continue
		}
		nested, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		for nestedKey := range nested {
			// Exact match only: the legacy nested keys are all-lowercase
			// forms of the new camelCase keys, so a case-insensitive match
			// would flag the new spelling too.
			if newKey, ok := legacyKeys[strings.ToLower(key)+"."+nestedKey]; ok {
				found = append(found, fmt.Sprintf("%q is now %q", key+"."+nestedKey, newKey))
			}
		}
	}
	if len(found) == 0 {
		return nil
	}
	sort.Strings(found)
	return fmt.Errorf("configuration uses the pre-v0.9 layout; please migrate: %s (see CHANGELOG.md for the full mapping)",
		strings.Join(found, "; "))
}

// parseConfig decodes the configuration, rejecting unknown fields and
// pre-v0.9 keys with a migration hint. ext is ".yaml", ".yml" or ".json".
func parseConfig(data []byte, ext string) (Config, error) {
	var config Config

	// First pass: decode generically to detect legacy keys with a helpful
	// message before the strict decode rejects them as unknown fields.
	raw := map[string]interface{}{}
	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return config, fmt.Errorf("failed to decode YAML configuration: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, &raw); err != nil {
			return config, fmt.Errorf("failed to decode JSON configuration: %w", err)
		}
	default:
		return config, fmt.Errorf("unsupported configuration file format: %s", ext)
	}
	if err := detectLegacyKeys(raw); err != nil {
		return config, err
	}

	// Second pass: strict decode, so typos and unknown keys fail loudly
	// instead of being silently ignored.
	switch ext {
	case ".yaml", ".yml":
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&config); err != nil {
			return config, fmt.Errorf("failed to decode YAML configuration: %w", err)
		}
	case ".json":
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			return config, fmt.Errorf("failed to decode JSON configuration: %w", err)
		}
	}
	return config, nil
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
	if redisTLS := os.Getenv("WHOIS_REDIS_TLS"); redisTLS != "" {
		config.Redis.TLS = redisTLS == "true" || redisTLS == "1"
	}
	if redisTLSSkipVerify := os.Getenv("WHOIS_REDIS_TLS_SKIP_VERIFY"); redisTLSSkipVerify != "" {
		config.Redis.TLSSkipVerify = redisTLSSkipVerify == "true" || redisTLSSkipVerify == "1"
	}

	// Override cache configuration
	if cacheExpiration := os.Getenv("WHOIS_CACHE_EXPIRATION"); cacheExpiration != "" {
		if cacheInt, err := strconv.Atoi(cacheExpiration); err == nil {
			config.Cache.Expiration = cacheInt
		}
	}
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
	if negativeCacheExpiration := os.Getenv("WHOIS_NEGATIVE_CACHE_EXPIRATION"); negativeCacheExpiration != "" {
		if exp, err := strconv.Atoi(negativeCacheExpiration); err == nil {
			config.Cache.NegativeExpiration = exp
		}
	}

	// Override server configuration
	if port := os.Getenv("WHOIS_PORT"); port != "" {
		if portInt, err := strconv.Atoi(port); err == nil {
			config.Server.Port = portInt
		}
	}
	if rateLimit := os.Getenv("WHOIS_RATE_LIMIT"); rateLimit != "" {
		if rateInt, err := strconv.Atoi(rateLimit); err == nil {
			config.Server.RateLimit = rateInt
		}
	}

	// Override bootstrap configuration
	if bootstrapInterval := os.Getenv("WHOIS_BOOTSTRAP_INTERVAL"); bootstrapInterval != "" {
		if intervalInt, err := strconv.Atoi(bootstrapInterval); err == nil {
			config.Bootstrap.Interval = intervalInt
		}
	}

	// Override proxy configuration
	if proxyServer := os.Getenv("WHOIS_PROXY_SERVER"); proxyServer != "" {
		config.Proxy.Server = proxyServer
	}
	if proxyUsername := os.Getenv("WHOIS_PROXY_USERNAME"); proxyUsername != "" {
		config.Proxy.Username = proxyUsername
	}
	if proxyPassword := os.Getenv("WHOIS_PROXY_PASSWORD"); proxyPassword != "" {
		config.Proxy.Password = proxyPassword
	}
	if proxySuffixes := os.Getenv("WHOIS_PROXY_SUFFIXES"); proxySuffixes != "" {
		config.Proxy.Suffixes = strings.Split(proxySuffixes, ",")
	}

	if logLevel := os.Getenv("WHOIS_LOG_LEVEL"); logLevel != "" {
		config.Log.Level = logLevel
	}
	if mcpProtection := os.Getenv("WHOIS_MCP_LOCALHOST_PROTECTION"); mcpProtection != "" {
		config.MCP.LocalhostProtection = mcpProtection == "true" || mcpProtection == "1"
	}

	// Override API authentication keys (comma-separated bare keys; the
	// name/rateLimit object form is config-file only)
	if authKeys := os.Getenv("WHOIS_AUTH_KEYS"); authKeys != "" {
		keys := []AuthKeySpec{}
		for _, key := range strings.Split(authKeys, ",") {
			if key = strings.TrimSpace(key); key != "" {
				keys = append(keys, AuthKeySpec{Key: key})
			}
		}
		config.Auth.Keys = keys
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
