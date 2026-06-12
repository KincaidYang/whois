package config

import (
	"bytes"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// AuthKeySpec is one entry of auth.keys. It accepts two forms:
//
//   - "secret"                       # bare string: anonymous key, no per-key limit
//   - {key: "secret", name: "ci", rateLimit: 120}
//
// Name labels the caller in logs and metrics (auto-named key1, key2, … when
// omitted); RateLimit is the per-key request budget in requests per minute
// (0 or omitted = unlimited).
type AuthKeySpec struct {
	Key       string `json:"key" yaml:"key"`
	Name      string `json:"name" yaml:"name"`
	RateLimit int    `json:"rateLimit" yaml:"rateLimit"`
}

// UnmarshalYAML accepts either a bare string or a mapping. Unknown fields in
// the mapping are rejected, preserving the strict parsing the rest of the
// config gets from yaml.Decoder.KnownFields (which does not reach inside
// custom unmarshalers).
func (s *AuthKeySpec) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		return value.Decode(&s.Key)
	}
	var fields map[string]yaml.Node
	if err := value.Decode(&fields); err != nil {
		return err
	}
	for name := range fields {
		switch name {
		case "key", "name", "rateLimit":
		default:
			return fmt.Errorf("unknown field %q in auth.keys entry", name)
		}
	}
	type plain AuthKeySpec
	var p plain
	if err := value.Decode(&p); err != nil {
		return err
	}
	*s = AuthKeySpec(p)
	return nil
}

// UnmarshalJSON accepts either a bare string or an object, mirroring
// UnmarshalYAML.
func (s *AuthKeySpec) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		return json.Unmarshal(data, &s.Key)
	}
	type plain AuthKeySpec
	var p plain
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return err
	}
	*s = AuthKeySpec(p)
	return nil
}

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
	// Auth holds API authentication settings.
	Auth struct {
		// Keys is the list of accepted API keys. Empty (the default) leaves
		// the service open; one or more keys protect every endpoint except
		// /health and /ready, which stay open for liveness probes. Clients
		// send a key as "Authorization: Bearer <key>" or "X-API-Key: <key>".
		// Entries are bare strings or {key, name, rateLimit} objects; see
		// AuthKeySpec.
		Keys []AuthKeySpec `json:"keys" yaml:"keys"`
	} `json:"auth" yaml:"auth"`
	// MCP holds settings for the MCP Streamable HTTP endpoint (/mcp).
	MCP struct {
		// LocalhostProtection enables DNS-rebinding protection, which rejects
		// requests whose Host header is not localhost. Keep false (default)
		// behind a reverse proxy, where the Host header is the public domain;
		// set true when the server is reached directly on localhost.
		LocalhostProtection bool `json:"localhostProtection" yaml:"localhostProtection"`
	} `json:"mcp" yaml:"mcp"`
}
