package config

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v2"
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

	// Open the configuration file
	configFile, err := os.Open("config.yaml")
	if err != nil {
		configFile, err = os.Open("config.json")
		if err != nil {
			log.Fatalf("Failed to open configuration file: %v", err)
		}
	}
	defer configFile.Close()

	// Determine the file type (JSON or YAML)
	fileExt := strings.ToLower(filepath.Ext(configFile.Name()))

	// Decode the configuration file
	if fileExt == ".yaml" || fileExt == ".yml" {
		decoder := yaml.NewDecoder(configFile)
		err = decoder.Decode(&config)
		if err != nil {
			log.Fatalf("Failed to decode YAML from configuration file: %v", err)
		}
	} else if fileExt == ".json" {
		decoder := json.NewDecoder(configFile)
		err = decoder.Decode(&config)
		if err != nil {
			log.Fatalf("Failed to decode JSON from configuration file: %v", err)
		}
	} else {
		log.Fatalf("Unsupported configuration file format: %s", fileExt)
	}

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
