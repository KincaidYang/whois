package config

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KincaidYang/whois/internal/utils"
	"github.com/redis/go-redis/v9"
)

func TestOverrideConfigWithEnvAllFields(t *testing.T) {
	t.Setenv("WHOIS_REDIS_ADDR", "redis.example:6380")
	t.Setenv("WHOIS_REDIS_PASSWORD", "secret")
	t.Setenv("WHOIS_REDIS_DB", "3")
	t.Setenv("WHOIS_REDIS_TLS", "true")
	t.Setenv("WHOIS_REDIS_TLS_SKIP_VERIFY", "1")
	t.Setenv("WHOIS_CACHE_EXPIRATION", "120")
	t.Setenv("WHOIS_REQUIRE_REDIS", "true")
	t.Setenv("WHOIS_MEMORY_MAX_SIZE", "500")
	t.Setenv("WHOIS_MEMORY_CLEAN_INTERVAL", "60")
	t.Setenv("WHOIS_NEGATIVE_CACHE_EXPIRATION", "30")
	t.Setenv("WHOIS_PORT", "9999")
	t.Setenv("WHOIS_RATE_LIMIT", "77")
	t.Setenv("WHOIS_PROXY_SERVER", "socks5://proxy.example:1080")
	t.Setenv("WHOIS_PROXY_USERNAME", "user")
	t.Setenv("WHOIS_PROXY_PASSWORD", "pass")
	t.Setenv("WHOIS_BATCH_ENABLED", "true")
	t.Setenv("WHOIS_BATCH_MAX_ITEMS", "42")
	t.Setenv("WHOIS_LOG_LEVEL", "debug")
	t.Setenv("WHOIS_MCP_LOCALHOST_PROTECTION", "false")

	var cfg Config
	cfg.MCP.LocalhostProtection = true
	overrideConfigWithEnv(&cfg)

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"redis.addr", cfg.Redis.Addr, "redis.example:6380"},
		{"redis.password", cfg.Redis.Password, "secret"},
		{"redis.db", cfg.Redis.DB, 3},
		{"redis.tls", cfg.Redis.TLS, true},
		{"redis.tlsSkipVerify", cfg.Redis.TLSSkipVerify, true},
		{"cache.expiration", cfg.Cache.Expiration, 120},
		{"cache.requireRedis", cfg.Cache.RequireRedis, true},
		{"cache.memoryMaxSize", cfg.Cache.MemoryMaxSize, 500},
		{"cache.memoryCleanInterval", cfg.Cache.MemoryCleanInterval, 60},
		{"cache.negativeExpiration", cfg.Cache.NegativeExpiration, 30},
		{"server.port", cfg.Server.Port, 9999},
		{"server.rateLimit", cfg.Server.RateLimit, 77},
		{"proxy.server", cfg.Proxy.Server, "socks5://proxy.example:1080"},
		{"proxy.username", cfg.Proxy.Username, "user"},
		{"proxy.password", cfg.Proxy.Password, "pass"},
		{"batch.enabled", cfg.Batch.Enabled, true},
		{"batch.maxItems", cfg.Batch.MaxItems, 42},
		{"log.level", cfg.Log.Level, "debug"},
		{"mcp.localhostProtection", cfg.MCP.LocalhostProtection, false},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestOverrideConfigWithEnvExplicitEmptyRedisAddr(t *testing.T) {
	// An explicitly empty WHOIS_REDIS_ADDR must clear a baked-in address
	// (memory-only mode); this is the LookupEnv-vs-Getenv distinction.
	t.Setenv("WHOIS_REDIS_ADDR", "")
	cfg := Config{}
	cfg.Redis.Addr = "baked-in:6379"
	overrideConfigWithEnv(&cfg)
	if cfg.Redis.Addr != "" {
		t.Errorf("redis.addr = %q, want cleared by explicit empty env", cfg.Redis.Addr)
	}
}

func TestOverrideConfigWithEnvBadNumbersIgnored(t *testing.T) {
	t.Setenv("WHOIS_PORT", "not-a-number")
	t.Setenv("WHOIS_REDIS_DB", "also-bad")
	cfg := Config{}
	cfg.Server.Port = 8043
	cfg.Redis.DB = 1
	overrideConfigWithEnv(&cfg)
	if cfg.Server.Port != 8043 || cfg.Redis.DB != 1 {
		t.Errorf("port/db = %d/%d, want unparseable env values ignored (8043/1)", cfg.Server.Port, cfg.Redis.DB)
	}
}

func TestInitLoggerLevels(t *testing.T) {
	old := slog.Default()
	t.Cleanup(func() { slog.SetDefault(old) })
	ctx := context.Background()

	cases := []struct {
		level      string
		enabledAt  slog.Level
		disabledAt slog.Level
	}{
		{"debug", slog.LevelDebug, slog.LevelDebug - 1},
		{"WARN", slog.LevelWarn, slog.LevelInfo},
		{"error", slog.LevelError, slog.LevelWarn},
		{"bogus", slog.LevelInfo, slog.LevelDebug}, // unknown value defaults to Info
	}
	for _, c := range cases {
		initLogger(c.level)
		if !slog.Default().Enabled(ctx, c.enabledAt) {
			t.Errorf("initLogger(%q): level %v should be enabled", c.level, c.enabledAt)
		}
		if slog.Default().Enabled(ctx, c.disabledAt) {
			t.Errorf("initLogger(%q): level %v should be disabled", c.level, c.disabledAt)
		}
	}
}

func TestReadConfigFile(t *testing.T) {
	t.Run("no file", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if _, _, err := readConfigFile(); err == nil {
			t.Error("want error when no config file exists")
		}
	})

	t.Run("yaml preferred", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("server:\n  port: 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		data, ext, err := readConfigFile()
		if err != nil || ext != ".yaml" || len(data) == 0 {
			t.Errorf("got ext %q err %v, want .yaml", ext, err)
		}
	})

	t.Run("json fallback", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, ext, err := readConfigFile()
		if err != nil || ext != ".json" {
			t.Errorf("got ext %q err %v, want .json", ext, err)
		}
	})

	t.Run("unreadable file", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		// A directory named config.yaml fails ReadFile with a non-NotExist
		// error, which must stop the search instead of falling through.
		if err := os.Mkdir(filepath.Join(dir, "config.yaml"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readConfigFile(); err == nil {
			t.Error("want error for unreadable config.yaml")
		}
	})
}

func TestInitVersionInfo(t *testing.T) {
	oldV, oldB, oldG := Version, BuildTime, GitCommit
	t.Cleanup(func() { Version, BuildTime, GitCommit = oldV, oldB, oldG })

	initVersionInfo()
	// Test binaries carry no release version or VCS stamps, so the documented
	// defaults must hold rather than leaving the fields empty.
	if Version == "" || BuildTime == "" || GitCommit == "" {
		t.Errorf("version info left empty: %q/%q/%q", Version, BuildTime, GitCommit)
	}
}

func TestInitializeCacheManagerMemoryOnly(t *testing.T) {
	oldClient, oldManager := RedisClient, CacheManager
	oldMax, oldInterval := MemoryMaxSize, MemoryCleanInterval
	t.Cleanup(func() {
		RedisClient, CacheManager = oldClient, oldManager
		MemoryMaxSize, MemoryCleanInterval = oldMax, oldInterval
	})

	RedisClient = nil
	MemoryMaxSize = 10
	MemoryCleanInterval = time.Minute

	initializeCacheManager()

	mc, ok := CacheManager.(*utils.MemoryCache)
	if !ok {
		t.Fatalf("CacheManager = %T, want *utils.MemoryCache in memory-only mode", CacheManager)
	}
	_ = mc.Close()
}

func TestInitializeCacheManagerRedisUnavailableFallback(t *testing.T) {
	oldClient, oldManager := RedisClient, CacheManager
	oldMax, oldInterval, oldRequire := MemoryMaxSize, MemoryCleanInterval, RequireRedis
	t.Cleanup(func() {
		RedisClient, CacheManager = oldClient, oldManager
		MemoryMaxSize, MemoryCleanInterval, RequireRedis = oldMax, oldInterval, oldRequire
	})

	// Port 1 refuses connections immediately: Redis is configured but down.
	RedisClient = redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 500 * time.Millisecond})
	t.Cleanup(func() { _ = RedisClient.Close() })
	MemoryMaxSize = 10
	MemoryCleanInterval = time.Minute
	RequireRedis = false

	initializeCacheManager()

	fc, ok := CacheManager.(*utils.FallbackCache)
	if !ok {
		t.Fatalf("CacheManager = %T, want *utils.FallbackCache with Redis configured", CacheManager)
	}
	if fc.IsPrimaryHealthy() {
		t.Error("primary must be unhealthy with Redis unreachable")
	}
	if !fc.IsHealthy() {
		t.Error("fallback memory cache must keep the manager healthy")
	}
	_ = fc.Close()
}
