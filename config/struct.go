package config

// Config represents the configuration for the application.
type Config struct {
	// Redis holds the configuration for the Redis database.
	// It includes the address, password, and database number.
	Redis struct {
		Addr     string `json:"addr" yaml:"addr"`         // Addr is the address of the Redis server.
		Password string `json:"password" yaml:"password"` // Password is the password for the Redis server.
		DB       int    `json:"db" yaml:"db"`             // DB is the database number for the Redis server.
	} `json:"redis" yaml:"redis"`
	// CacheExpiration is the expiration time for the cache, in seconds.
	CacheExpiration int `json:"cacheExpiration" yaml:"cacheexpiration"`
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
}
