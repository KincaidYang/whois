package config

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v3"
)

var (
	// redisClient is the Redis client
	RedisClient *redis.Client
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
)

func init() {
	var config Config

	// Load configuration from file
	loadConfigFromFile(&config)

	// Override configuration with environment variables if they exist
	overrideConfigWithEnv(&config)

	// Initialize the Redis client
	RedisClient = redis.NewClient(&redis.Options{
		Addr:     config.Redis.Addr,
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})

	// Set the cache expiration time
	CacheExpiration = time.Duration(config.CacheExpiration) * time.Second

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
	if fileExt == ".yaml" || fileExt == ".yml" {
		decoder := yaml.NewDecoder(configFile)
		err = decoder.Decode(config)
		if err != nil {
			log.Fatalf("Failed to decode YAML from configuration file: %v", err)
		}
	} else if fileExt == ".json" {
		decoder := json.NewDecoder(configFile)
		err = decoder.Decode(config)
		if err != nil {
			log.Fatalf("Failed to decode JSON from configuration file: %v", err)
		}
	} else {
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
