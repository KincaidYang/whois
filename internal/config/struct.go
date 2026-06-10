package config

// Config represents the configuration for the application. YAML and JSON tags
// are identical camelCase; keys from the pre-v0.9 flat layout are rejected at
// load time with a migration hint (see legacyKeys in config.go).
type Config struct {
	// Server holds the HTTP server settings.
	Server struct {
		// Port is the port number the server listens on (default: 8043).
		Port int `json:"port" yaml:"port"`
		// RateLimit is the maximum number of concurrent requests (default: 100).
		RateLimit int `json:"rateLimit" yaml:"rateLimit"`
	} `json:"server" yaml:"server"`
	// Log holds logging settings.
	Log struct {
		// Level sets the minimum log level: debug, info, warn, error (default: info).
		Level string `json:"level" yaml:"level"`
	} `json:"log" yaml:"log"`
	// Cache holds cache settings.
	Cache struct {
		// Expiration is how long (in seconds) successful results are cached
		// (default: 3600).
		Expiration int `json:"expiration" yaml:"expiration"`
		// NegativeExpiration is how long (in seconds) "not found" / "denied"
		// results are cached to avoid hammering upstream servers. Default: 60.
		// Set to a negative value to disable negative caching.
		NegativeExpiration int `json:"negativeExpiration" yaml:"negativeExpiration"`
		// RequireRedis makes startup fail when Redis is unavailable instead of
		// falling back to the in-memory cache (default: false).
		RequireRedis bool `json:"requireRedis" yaml:"requireRedis"`
		// MemoryMaxSize is the maximum number of entries in the in-memory
		// fallback cache (default: 10000).
		MemoryMaxSize int `json:"memoryMaxSize" yaml:"memoryMaxSize"`
		// MemoryCleanInterval is the interval (in seconds) for evicting expired
		// in-memory entries (default: 300).
		MemoryCleanInterval int `json:"memoryCleanInterval" yaml:"memoryCleanInterval"`
	} `json:"cache" yaml:"cache"`
	// Redis holds the connection settings for the Redis cache backend.
	Redis struct {
		Addr     string `json:"addr" yaml:"addr"`
		Password string `json:"password" yaml:"password"`
		DB       int    `json:"db" yaml:"db"`
		// TLS enables TLS for the Redis connection. Use when Redis is reached
		// over an untrusted network so the password is not sent in cleartext.
		TLS bool `json:"tls" yaml:"tls"`
		// TLSSkipVerify disables server certificate verification (not
		// recommended; only for self-signed certificates in trusted networks).
		TLSSkipVerify bool `json:"tlsSkipVerify" yaml:"tlsSkipVerify"`
	} `json:"redis" yaml:"redis"`
	// Proxy routes RDAP queries for selected TLDs through an HTTP proxy.
	Proxy struct {
		// Server is the proxy URL; empty disables proxying.
		Server   string `json:"server" yaml:"server"`
		Username string `json:"username" yaml:"username"`
		Password string `json:"password" yaml:"password"`
		// Suffixes is the list of TLDs queried through the proxy; the special
		// value "all" proxies every TLD.
		Suffixes []string `json:"suffixes" yaml:"suffixes"`
	} `json:"proxy" yaml:"proxy"`
	// Bootstrap controls refreshing RDAP server lists from IANA.
	Bootstrap struct {
		// Interval is how often (in seconds) to refresh. 0 or unset disables
		// all fetching; the default config.yaml sets 86400 (24 hours).
		Interval int `json:"interval" yaml:"interval"`
	} `json:"bootstrap" yaml:"bootstrap"`
	// MCP holds settings for the MCP Streamable HTTP endpoint (/mcp).
	MCP struct {
		// LocalhostProtection enables DNS-rebinding protection, which rejects
		// requests whose Host header is not localhost. Keep false (default)
		// behind a reverse proxy, where the Host header is the public domain;
		// set true when the server is reached directly on localhost.
		LocalhostProtection bool `json:"localhostProtection" yaml:"localhostProtection"`
	} `json:"mcp" yaml:"mcp"`
}
