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
auth:
  keys: ["key-one", "key-two"]
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
	if len(cfg.Auth.Keys) != 2 || cfg.Auth.Keys[0].Key != "key-one" {
		t.Errorf("auth.keys: %+v", cfg.Auth.Keys)
	}
}

func TestParseConfigAuthKeyObjects(t *testing.T) {
	cfg, err := parseConfig([]byte(`
auth:
  keys:
    - "bare-secret"
    - key: "named-secret"
      name: "ci"
      rateLimit: 120
`), ".yaml")
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if len(cfg.Auth.Keys) != 2 {
		t.Fatalf("auth.keys: %+v", cfg.Auth.Keys)
	}
	if cfg.Auth.Keys[0] != (AuthKeySpec{Key: "bare-secret"}) {
		t.Errorf("bare entry: %+v", cfg.Auth.Keys[0])
	}
	if cfg.Auth.Keys[1] != (AuthKeySpec{Key: "named-secret", Name: "ci", RateLimit: 120}) {
		t.Errorf("object entry: %+v", cfg.Auth.Keys[1])
	}
}

func TestParseConfigAuthKeyObjectUnknownField(t *testing.T) {
	_, err := parseConfig([]byte("auth:\n  keys:\n    - key: \"k\"\n      limit: 5\n"), ".yaml")
	if err == nil || !strings.Contains(err.Error(), `unknown field "limit"`) {
		t.Errorf("expected unknown-field error, got %v", err)
	}
}

func TestParseConfigAuthKeyObjectsJSON(t *testing.T) {
	cfg, err := parseConfig([]byte(`{"auth": {"keys": ["bare", {"key": "k2", "name": "ci", "rateLimit": 60}]}}`), ".json")
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.Auth.Keys[0].Key != "bare" || cfg.Auth.Keys[1] != (AuthKeySpec{Key: "k2", Name: "ci", RateLimit: 60}) {
		t.Errorf("auth.keys from json: %+v", cfg.Auth.Keys)
	}

	if _, err := parseConfig([]byte(`{"auth": {"keys": [{"key": "k", "limit": 5}]}}`), ".json"); err == nil {
		t.Error("expected unknown-field error for json object entry")
	}
}

func TestNormalizeAuthClients(t *testing.T) {
	clients, err := normalizeAuthClients([]AuthKeySpec{
		{Key: " padded "},
		{Key: "plain", Name: "ci", RateLimit: 60},
	})
	if err != nil {
		t.Fatalf("normalizeAuthClients: %v", err)
	}
	if clients[0] != (AuthClient{Key: "padded", Name: "key1"}) {
		t.Errorf("auto-named client: %+v", clients[0])
	}
	if clients[1].Key != "plain" || clients[1].Name != "ci" || clients[1].RateLimit != 60 {
		t.Errorf("named client: %+v", clients[1])
	}
	if clients[0].Limiter != nil {
		t.Error("unlimited client should have no limiter")
	}
	if l := clients[1].Limiter; l == nil || l.Limit() != 1 || l.Burst() != 60 {
		t.Errorf("limited client: limiter %+v, want rate 1/s burst 60", clients[1].Limiter)
	}

	for name, bad := range map[string][]AuthKeySpec{
		"empty key":          {{Key: ""}},
		"blank key":          {{Key: "   "}},
		"empty among ok":     {{Key: "ok"}, {Key: ""}},
		"duplicate key":      {{Key: "same"}, {Key: "same"}},
		"duplicate name":     {{Key: "a", Name: "ci"}, {Key: "b", Name: "ci"}},
		"name with space":    {{Key: "a", Name: "my ci"}},
		"negative rateLimit": {{Key: "a", RateLimit: -1}},
	} {
		if _, err := normalizeAuthClients(bad); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}

	if clients, err := normalizeAuthClients(nil); err != nil || len(clients) != 0 {
		t.Errorf("nil specs: got %+v, %v", clients, err)
	}
}

func TestEnvOverrideAuthKeys(t *testing.T) {
	t.Setenv("WHOIS_AUTH_KEYS", "k1, k2 ,,k3")
	var cfg Config
	overrideConfigWithEnv(&cfg)
	if len(cfg.Auth.Keys) != 3 || cfg.Auth.Keys[0].Key != "k1" || cfg.Auth.Keys[1].Key != "k2" || cfg.Auth.Keys[2].Key != "k3" {
		t.Errorf("auth.keys from env: %+v", cfg.Auth.Keys)
	}
}

func TestEnvOverrideBootstrapInterval(t *testing.T) {
	t.Setenv("WHOIS_BOOTSTRAP_INTERVAL", "3600")
	var cfg Config
	overrideConfigWithEnv(&cfg)
	if cfg.Bootstrap.Interval != 3600 {
		t.Errorf("bootstrap.interval from env: %d, want 3600", cfg.Bootstrap.Interval)
	}

	t.Setenv("WHOIS_BOOTSTRAP_INTERVAL", "not-a-number")
	cfg = Config{}
	cfg.Bootstrap.Interval = 86400
	overrideConfigWithEnv(&cfg)
	if cfg.Bootstrap.Interval != 86400 {
		t.Errorf("invalid env should keep existing value: %d, want 86400", cfg.Bootstrap.Interval)
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

func TestValidateConfigNegativeValues(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"server.port", func(c *Config) { c.Server.Port = -1 }},
		{"server.rateLimit", func(c *Config) { c.Server.RateLimit = -1 }},
		{"cache.expiration", func(c *Config) { c.Cache.Expiration = -1 }},
		{"cache.memoryMaxSize", func(c *Config) { c.Cache.MemoryMaxSize = -1 }},
		{"cache.memoryCleanInterval", func(c *Config) { c.Cache.MemoryCleanInterval = -1 }},
		{"bootstrap.interval", func(c *Config) { c.Bootstrap.Interval = -1 }},
		{"batch.maxItems", func(c *Config) { c.Batch.MaxItems = -1 }},
	}
	for _, tc := range cases {
		var cfg Config
		applyDefaults(&cfg)
		tc.mutate(&cfg)
		err := validateConfig(&cfg)
		if err == nil {
			t.Errorf("%s: expected error for negative value", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.name) {
			t.Errorf("%s: error %q does not name the offending key", tc.name, err)
		}
	}
}

func TestValidateConfigDefaultsPass(t *testing.T) {
	var cfg Config
	applyDefaults(&cfg)
	if err := validateConfig(&cfg); err != nil {
		t.Errorf("defaults must validate: %v", err)
	}

	// The documented "disable" value for negative caching must stay accepted.
	cfg.Cache.NegativeExpiration = -1
	if err := validateConfig(&cfg); err != nil {
		t.Errorf("negative cache.negativeExpiration must stay valid: %v", err)
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
