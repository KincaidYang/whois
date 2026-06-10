package config

import (
	"strings"
	"testing"
)

const validYAML = `
server:
  port: 9999
  rateLimit: 7
log:
  level: "debug"
cache:
  expiration: 1234
  negativeExpiration: 30
  requireRedis: true
  memoryMaxSize: 50
  memoryCleanInterval: 60
redis:
  addr: "redis.example:6379"
  password: "secret"
  db: 2
  tls: true
  tlsSkipVerify: true
proxy:
  server: "http://proxy.example:8080"
  username: "u"
  password: "p"
  suffixes: ["cn", "jp"]
bootstrap:
  interval: 3600
mcp:
  localhostProtection: true
`

func TestParseConfigYAML(t *testing.T) {
	cfg, err := parseConfig([]byte(validYAML), ".yaml")
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.Server.Port != 9999 || cfg.Server.RateLimit != 7 {
		t.Errorf("server: %+v", cfg.Server)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("log.level: %q", cfg.Log.Level)
	}
	if cfg.Cache.Expiration != 1234 || cfg.Cache.NegativeExpiration != 30 ||
		!cfg.Cache.RequireRedis || cfg.Cache.MemoryMaxSize != 50 || cfg.Cache.MemoryCleanInterval != 60 {
		t.Errorf("cache: %+v", cfg.Cache)
	}
	if cfg.Redis.Addr != "redis.example:6379" || !cfg.Redis.TLS || !cfg.Redis.TLSSkipVerify || cfg.Redis.DB != 2 {
		t.Errorf("redis: %+v", cfg.Redis)
	}
	if cfg.Proxy.Server != "http://proxy.example:8080" || len(cfg.Proxy.Suffixes) != 2 {
		t.Errorf("proxy: %+v", cfg.Proxy)
	}
	if cfg.Bootstrap.Interval != 3600 {
		t.Errorf("bootstrap.interval: %d", cfg.Bootstrap.Interval)
	}
	if !cfg.MCP.LocalhostProtection {
		t.Errorf("mcp.localhostProtection: false")
	}
}

func TestParseConfigJSON(t *testing.T) {
	cfg, err := parseConfig([]byte(`{"server": {"port": 8080}, "log": {"level": "warn"}}`), ".json")
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.Server.Port != 8080 || cfg.Log.Level != "warn" {
		t.Errorf("got %+v", cfg)
	}
}

func TestParseConfigLegacyTopLevelKeys(t *testing.T) {
	legacy := `
redis:
  addr: "127.0.0.1:6379"
cacheexpiration: 3600
port: 8043
ratelimit: 60
loglevel: "info"
`
	_, err := parseConfig([]byte(legacy), ".yaml")
	if err == nil {
		t.Fatal("expected migration error for legacy keys")
	}
	for _, hint := range []string{"pre-v0.9", `"cacheexpiration" is now "cache.expiration"`, `"port" is now "server.port"`, `"ratelimit" is now "server.rateLimit"`, `"loglevel" is now "log.level"`} {
		if !strings.Contains(err.Error(), hint) {
			t.Errorf("error %q missing hint %q", err, hint)
		}
	}
}

func TestParseConfigLegacyNestedKeys(t *testing.T) {
	legacy := `
redis:
  addr: "127.0.0.1:6379"
  tlsskipverify: true
cache:
  requireredis: true
  negativecacheexpiration: 60
mcp:
  localhostprotection: true
`
	_, err := parseConfig([]byte(legacy), ".yaml")
	if err == nil {
		t.Fatal("expected migration error for legacy nested keys")
	}
	for _, hint := range []string{`"redis.tlsskipverify" is now "redis.tlsSkipVerify"`, `"cache.requireredis" is now "cache.requireRedis"`, `"cache.negativecacheexpiration" is now "cache.negativeExpiration"`, `"mcp.localhostprotection" is now "mcp.localhostProtection"`} {
		if !strings.Contains(err.Error(), hint) {
			t.Errorf("error %q missing hint %q", err, hint)
		}
	}
}

func TestParseConfigLegacyJSONKeys(t *testing.T) {
	// The legacy JSON layout used camelCase top-level keys; the migration
	// check matches them case-insensitively.
	_, err := parseConfig([]byte(`{"cacheExpiration": 3600, "logLevel": "info"}`), ".json")
	if err == nil || !strings.Contains(err.Error(), `"cacheExpiration" is now "cache.expiration"`) {
		t.Errorf("expected migration error, got %v", err)
	}
}

func TestParseConfigUnknownKey(t *testing.T) {
	_, err := parseConfig([]byte("server:\n  prot: 8043\n"), ".yaml")
	if err == nil {
		t.Fatal("expected error for unknown key (typo)")
	}
}

func TestParseConfigUnsupportedExt(t *testing.T) {
	if _, err := parseConfig([]byte("x"), ".toml"); err == nil {
		t.Fatal("expected error for unsupported extension")
	}
}

func TestApplyDefaults(t *testing.T) {
	var cfg Config
	applyDefaults(&cfg)
	if cfg.Server.Port != 8043 || cfg.Server.RateLimit != 100 {
		t.Errorf("server defaults: %+v", cfg.Server)
	}
	if cfg.Cache.Expiration != 3600 || cfg.Cache.NegativeExpiration != 60 ||
		cfg.Cache.MemoryMaxSize != 10000 || cfg.Cache.MemoryCleanInterval != 300 {
		t.Errorf("cache defaults: %+v", cfg.Cache)
	}

	// A negative value disables negative caching and must survive defaulting.
	cfg.Cache.NegativeExpiration = -1
	applyDefaults(&cfg)
	if cfg.Cache.NegativeExpiration != -1 {
		t.Errorf("negative NegativeExpiration overwritten: %d", cfg.Cache.NegativeExpiration)
	}
}
