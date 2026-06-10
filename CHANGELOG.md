# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> ⚠️ **Heads-up:** the 0.x releases leading up to v1.0.0 will include
> **breaking changes** to the API response format and the configuration file.
> Each breaking change is listed under a **Breaking** heading below. After
> v1.0.0 the API and configuration format will remain stable.

## [Unreleased]

### Breaking
- **API response format rewritten to align with RDAP (RFC 9083).** All field
  names are now camelCase and follow RDAP vocabulary. Every successful
  response carries an `objectClassName` discriminator (`domain` /
  `ip network` / `autnum`). Field mapping:

  | Old (domain) | New |
  |---|---|
  | `Domain Name` | `ldhName` (lowercase; `unicodeName` added for IDNs) |
  | `Registrar` | `registrar` |
  | `Registrar IANA ID` | `registrarIanaId` |
  | `Domain Status` | `status` (ICANN EPP reference URLs stripped, deduped) |
  | `Creation Date` | `registrationDate` |
  | `Registry Expiry Date` | `expirationDate` |
  | `Updated Date` | `lastChangedDate` |
  | `Name Server` | `nameservers` (lowercase) |
  | `DNSSEC` + `DNSSEC DS Data` | `secureDNS` object: `{delegationSigned, dsData: [{keyTag, algorithm, digestType, digest}]}` |
  | `Last Update of Database` | `lastUpdateOfRdapDb` |

  | Old (IP network) | New |
  |---|---|
  | `IP Network` | `handle` |
  | `Address Range` | `startAddress` + `endAddress` (split) |
  | `Network Name` | `name` |
  | `CIDR` | `cidr` |
  | `Network Type` | `type` (empty instead of `"Unknown"` filler) |
  | `Country` | `country` |
  | `Status` | `status` |
  | `Creation Date` | `registrationDate` |
  | `Updated Date` | `lastChangedDate` |
  | `Remarks` | `remarks` |

  | Old (ASN) | New |
  |---|---|
  | `AS Number` | `handle` |
  | `Network Name` | `name` |
  | `Status` | `status` |
  | `Creation Date` | `registrationDate` |
  | `Updated Date` | `lastChangedDate` |

- **Dates normalized to RFC 3339 UTC** across all sources (RDAP and the
  built-in ccTLD WHOIS parsers). Registry-local timestamps (.cn/.tw/.mo/.sg
  UTC+8, .jp UTC+9) are converted to UTC. Date-only values stay `YYYY-MM-DD`.
- **Errors are now RFC 9457 Problem Details** (`application/problem+json`)
  with `{type, title, status, detail}`; the `type` URI points to an anchor in
  [docs/errors.md](docs/errors.md). The old `{"error": ...}` shape is gone.
- **Domains whose TLD has no parser now return JSON**
  (`{"objectClassName": "domain", "unparsed": true, "rawText": "..."}`)
  instead of `text/plain`. Only `?raw=1` returns plain text.
- Cache keys moved from `whois:` to `whois:v2:`; existing cache entries are
  abandoned (no migration needed, they expire naturally).

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
