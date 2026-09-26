package config

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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
	if err := overrideConfigWithEnv(&cfg); err != nil {
		t.Fatal(err)
	}

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
	if err := overrideConfigWithEnv(&cfg); err != nil {
		t.Fatal(err)
	}
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
	if err := overrideConfigWithEnv(&cfg); err != nil {
		t.Fatal(err)
	}
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

// TestLoadConfig covers every way loadConfig refuses startup, plus the
// happy path, against a configuration file in a temporary working directory.
func TestLoadConfig(t *testing.T) {
	writeConfig := func(t *testing.T, name, content string) {
		t.Helper()
		dir := t.TempDir()
		t.Chdir(dir)
		if name != "" {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	t.Run("no file", func(t *testing.T) {
		writeConfig(t, "", "")
		if _, _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "failed to open configuration file") {
			t.Fatalf("err = %v, want a missing-file error", err)
		}
	})
	t.Run("unparseable", func(t *testing.T) {
		writeConfig(t, "config.yaml", "server: [unclosed")
		if _, _, err := loadConfig(); err == nil {
			t.Fatal("expected a parse error")
		}
	})
	t.Run("keyless auth env", func(t *testing.T) {
		writeConfig(t, "config.yaml", "auth:\n  keys:\n    - key: from-file\n")
		t.Setenv("WHOIS_AUTH_KEYS", " , ")
		if _, _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "WHOIS_AUTH_KEYS") {
			t.Fatalf("err = %v, want the WHOIS_AUTH_KEYS error", err)
		}
	})
	t.Run("invalid value", func(t *testing.T) {
		writeConfig(t, "config.yaml", "server:\n  rateLimit: -1\n")
		if _, _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "server.rateLimit") {
			t.Fatalf("err = %v, want the negative rateLimit error", err)
		}
	})
	t.Run("upstreamLimit follows rateLimit, or its own env", func(t *testing.T) {
		writeConfig(t, "config.yaml", "server:\n  rateLimit: 30\n")
		cfg, _, err := loadConfig()
		if err != nil || cfg.Server.UpstreamLimit != 30 {
			t.Fatalf("upstreamLimit = %d, %v; want it to default to rateLimit (30)", cfg.Server.UpstreamLimit, err)
		}
		t.Setenv("WHOIS_UPSTREAM_LIMIT", "7")
		if cfg, _, err = loadConfig(); err != nil || cfg.Server.UpstreamLimit != 7 {
			t.Fatalf("upstreamLimit = %d, %v; want the env override (7)", cfg.Server.UpstreamLimit, err)
		}
		t.Setenv("WHOIS_UPSTREAM_LIMIT", "-1")
		if _, _, err = loadConfig(); err == nil || !strings.Contains(err.Error(), "server.upstreamLimit") {
			t.Fatalf("err = %v, want the negative upstreamLimit error", err)
		}
	})
	t.Run("invalid auth entry", func(t *testing.T) {
		writeConfig(t, "config.yaml", "auth:\n  keys:\n    - key: same\n    - key: same\n")
		if _, _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "duplicate key") {
			t.Fatalf("err = %v, want the duplicate-key error", err)
		}
	})
	t.Run("valid", func(t *testing.T) {
		writeConfig(t, "config.yaml", "server:\n  port: 9000\n")
		t.Setenv("WHOIS_AUTH_KEYS", "k1")
		cfg, clients, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig: %v", err)
		}
		if len(clients) != 1 || clients[0].Key != "k1" || clients[0].Name != "key1" {
			t.Errorf("clients = %+v, want one normalized client for k1", clients)
		}
		if cfg.Server.Port != 9000 || cfg.Server.RateLimit != 100 || cfg.Server.UpstreamLimit != 100 {
			t.Errorf("server = %+v, want the file's port, the default rateLimit and upstreamLimit following it", cfg.Server)
		}
		if len(cfg.Auth.Keys) != 1 || cfg.Auth.Keys[0].Key != "k1" {
			t.Errorf("auth.keys = %+v, want the env override", cfg.Auth.Keys)
		}
	})
}
