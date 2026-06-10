package config

// Config represents the configuration for the application.
type Config struct {
	// Redis holds the configuration for the Redis database.
	// It includes the address, password, and database number.
	Redis struct {
		Addr     string `json:"addr" yaml:"addr"`         // Addr is the address of the Redis server.
		Password string `json:"password" yaml:"password"` // Password is the password for the Redis server.
		DB       int    `json:"db" yaml:"db"`             // DB is the database number for the Redis server.
		// TLS enables TLS for the Redis connection. Use when Redis is reached
		// over an untrusted network so the password is not sent in cleartext.
		TLS bool `json:"tls" yaml:"tls"`
		// TLSSkipVerify disables server certificate verification (not
		// recommended; only for self-signed certificates in trusted networks).
		TLSSkipVerify bool `json:"tlsSkipVerify" yaml:"tlsskipverify"`
	} `json:"redis" yaml:"redis"`
	// CacheExpiration is the expiration time for the cache, in seconds.
	CacheExpiration int `json:"cacheExpiration" yaml:"cacheexpiration"`
	// Cache holds advanced cache configuration (optional, for backward compatibility)
	Cache struct {
		RequireRedis        bool `json:"requireRedis" yaml:"requireredis"`               // RequireRedis determines if Redis is required (default: false)
		MemoryMaxSize       int  `json:"memoryMaxSize" yaml:"memorymaxsize"`             // MemoryMaxSize is the maximum number of entries in memory cache (default: 10000)
		MemoryCleanInterval int  `json:"memoryCleanInterval" yaml:"memorycleaninterval"` // MemoryCleanInterval is the interval to clean expired entries in seconds (default: 300)
		// NegativeCacheExpiration is how long (in seconds) "not found" / "denied"
		// results are cached to avoid hammering upstream servers. Default: 60.
		// Set to a negative value to disable negative caching.
		NegativeCacheExpiration int `json:"negativeCacheExpiration" yaml:"negativecacheexpiration"`
	} `json:"cache" yaml:"cache"`
	// Port is the port number for the server.
	Port int `json:"port" yaml:"port"`
	// RateLimit is the maximum number of requests that a client can make in a specified period of time.
	RateLimit int `json:"ratelimit" yaml:"ratelimit"`
	// ProxyServer is the proxy server to use for certain TLDs.
	ProxyServer string `json:"proxyServer" yaml:"proxyserver"`
	// ProxyUsername is the username for the proxy server.
	ProxyUsername string `json:"proxyUsername" yaml:"proxyusername"`
	// ProxyPassword is the password for the proxy server.
	ProxyPassword string `json:"proxyPassword" yaml:"proxypassword"`
	// ProxySuffixes is the list of TLDs that use a proxy server.
	ProxySuffixes []string `json:"proxySuffixes" yaml:"proxysuffixes"`
	// LogLevel sets the minimum log level: debug, info, warn, error (default: info).
	LogLevel string `json:"logLevel" yaml:"loglevel"`
	// BootstrapInterval is how often (in seconds) to refresh RDAP server lists
	// from IANA bootstrap data. 0 or unset disables all fetching; set to 86400
	// in the default config.yaml to enable 24-hour refresh.
	BootstrapInterval int `json:"bootstrapInterval" yaml:"bootstrapinterval"`
	// MCP holds settings for the MCP Streamable HTTP endpoint (/mcp).
	MCP struct {
		// LocalhostProtection enables DNS-rebinding protection, which rejects
		// requests whose Host header is not localhost. Keep false (default)
		// behind a reverse proxy, where the Host header is the public domain;
		// set true when the server is reached directly on localhost.
		LocalhostProtection bool `json:"localhostProtection" yaml:"localhostprotection"`
	} `json:"mcp" yaml:"mcp"`
}
