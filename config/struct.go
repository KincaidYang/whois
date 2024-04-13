package config

// Config represents the configuration for the application.
type Config struct {
	// Redis holds the configuration for the Redis database.
	// It includes the address, password, and database number.
	Redis struct {
		Addr     string `json:"addr"`     // Addr is the address of the Redis server.
		Password string `json:"password"` // Password is the password for the Redis server.
		DB       int    `json:"db"`       // DB is the database number for the Redis server.
	} `json:"redis"`
	// CacheExpiration is the expiration time for the cache, in seconds.
	CacheExpiration int `json:"cacheExpiration"`
	// Port is the port number for the server.
	Port int `json:"port"`
	// RateLimit is the maximum number of requests that a client can make in a specified period of time.
	RateLimit int `json:"rateLimit"`
}
