# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> ⚠️ **Heads-up:** the 0.x releases leading up to v1.0.0 will include
> **breaking changes** to the API response format and the configuration file.
> Each breaking change is listed under a **Breaking** heading below. After
> v1.0.0 the API and configuration format will remain stable.

## [Unreleased]

### Changed
- All Go packages moved under `internal/` and renamed to idiomatic Go names
  (`handle_resources`→`handlers`, `server_lists`→`serverlist`,
  `rdap_tools`→`rdap`, `rdap_tools/structs`→`model`, `whois_tools`→`whois`,
  `mcp_server`→`mcp`). No behavior change; the module no longer exposes any
  importable Go API.

### Added
- `CHANGELOG.md` (this file) and `SECURITY.md`.
- golangci-lint in CI.

## [0.7.0] - 2026-06-10

### Added
- Request trace ID: `X-Request-ID` accepted/generated per request, returned in
  the response and attached to all logs for that request.
- `?raw=1` on domain queries returns the unparsed WHOIS response as
  `text/plain` (cached separately).
- MCP Streamable HTTP endpoint at `/mcp`.
- Negative caching of not-found/denied results
  (`cache.negativecacheexpiration`, default 60s).
- Redis TLS options (`redis.tls`, `redis.tlsskipverify`).
- Per-TLD Prometheus metrics, bootstrap gauges, cache eviction counter.

### Changed
- Error responses no longer leak internal error details; full errors go to
  logs only.
- Concurrent cache misses for the same key now share one upstream request
  (singleflight).
- Upstream WHOIS/RDAP responses capped at 2 MiB; oversized responses are
  rejected instead of truncated.
- In-memory cache is a true LRU with bounded size.
- Fully-IDN domains (e.g. `例子.中国`) accepted; IDN input converted to
  punycode at entry.

### Fixed
- MCP endpoint now respects concurrency limits, request timeout, and graceful
  shutdown like the main handler.
- MCP DNS-rebinding protection made configurable
  (`mcp.localhostprotection`, default off for reverse-proxy deployments).

## [0.6.0] - 2026-04-05

See the [release notes](https://github.com/KincaidYang/whois/releases/tag/v0.6.0).

## Older releases

See the [GitHub releases page](https://github.com/KincaidYang/whois/releases)
for 0.5.x and earlier.

[Unreleased]: https://github.com/KincaidYang/whois/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/KincaidYang/whois/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/KincaidYang/whois/compare/v0.5.4...v0.6.0
