# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> ✅ **v1.0.0 is the first stable release.** The HTTP API, error format,
> configuration file layout and `WHOIS_*` environment variables now follow
> [Semantic Versioning](https://semver.org/): incompatible changes will only
> land in a future major release. The 0.x history below includes the breaking
> changes made on the way to 1.0.0 (each under a **Breaking** heading).

## [1.1.0] - 2026-07-11

### Added
- Prebuilt release binaries for `linux/loong64` (LoongArch, new-world ABI).

### Security
- Builds now require Go 1.26.5, picking up the upstream `crypto/tls` fix for
  [GO-2026-5856](https://pkg.go.dev/vuln/GO-2026-5856), which was reachable from
  this binary.
- Responses carry `Cache-Control: private` (instead of `public`) when API key
  authentication is enabled, so a shared cache such as a CDN in front of an
  authenticated instance cannot serve cached results to clients that never
  presented a key. Open instances keep `public`.
- An invalid `proxy.server` URL now fails startup instead of being silently
  dropped at first use, which sent traffic the operator meant to route through
  the proxy over the direct connection instead. `proxy.suffixes` entries are
  lowercased on load to match the lookup side; an uppercase suffix could never
  match before.

### Fixed
- Redis cache no longer treats a caller's cancelled/expired request context as a
  Redis failure. Previously a single client disconnecting mid-request could flip
  the shared connection to "unhealthy", forcing every other in-flight request onto
  the memory-only fallback until the next 30s health check. Genuine Redis command
  errors are now also logged and counted (`whois_cache_requests_total{result="error"}`).
- Boolean environment overrides (`WHOIS_REDIS_TLS`, `WHOIS_REDIS_TLS_SKIP_VERIFY`,
  `WHOIS_REQUIRE_REDIS`, `WHOIS_BATCH_ENABLED`, `WHOIS_MCP_LOCALHOST_PROTECTION`) no
  longer silently coerce an unrecognized value to `false`. Values are now parsed
  case-insensitively (`true`/`1`/`false`/`0`); anything else keeps the existing
  setting and logs a warning, so a typo like `True`/`yes` can't quietly disable a
  security-relevant flag such as `redis.tls`.
- The `.la` `Registrar IANA ID` field is now parsed correctly. A stray end-of-input
  anchor in the regex meant the field was only ever captured when it happened to be
  the last line of the response, so it was effectively always empty.
- `.hk`, `.tw` and `.mo` responses now have CRLF line endings normalized before
  parsing (as `.au` already did), so the nameserver list is no longer silently
  dropped when the registry uses `\r\n`.
- The `/mcp` endpoint now caps its request body (256 KiB), matching the existing
  limit on `/batch`; previously the MCP transport read the whole request into
  memory without bound.
- Graceful shutdown now stops accepting new requests before waiting for in-flight
  ones. The previous order waited on the in-flight counter while the listener was
  still admitting requests, so under sustained traffic shutdown could hang
  indefinitely; both waits are now bounded.
- A request whose client disconnects (or whose batch item deadline passes) while
  waiting on a deduplicated upstream query now returns immediately instead of
  blocking for the full query timeout. The shared upstream query still runs to
  completion and populates the cache, and keeps a concurrency slot occupied until
  it finishes, so `server.rateLimit` remains a true cap on concurrent upstream
  work.
- `/batch` rejects request bodies with trailing data after the JSON object;
  previously a valid object followed by a second JSON document was accepted with
  the remainder silently ignored.
- The OpenAPI document now declares that every endpoint accepts anonymous, bearer
  or `X-API-Key` access (enforced only when `auth.keys` is configured) — it
  previously defined the security schemes without any security requirement — and
  CIDR queries are described by a dedicated `/ip/{address}/{prefixlen}` entry
  instead of a path parameter containing a slash, which OpenAPI does not allow.
  Runtime routing is unchanged.

### Changed
- The compiled-in IANA baseline lists were regenerated from live IANA data
  (July 2026): every root-zone TLD was re-verified against `whois.iana.org`.
  This picks up registry migrations (Tucows TLDs to `registry.click`,
  Chinese gTLDs consolidated on `zdns.cn`/`rdap.ngtld.cn`, `.link`, `.music`,
  and others), the new `.merck` TLD, and three new RIPE ASN ranges. Instances
  with `bootstrap.interval` enabled already receive the RDAP portion at
  runtime; the WHOIS TLD map and offline fallbacks now match as well.
- The `/mcp` endpoint now runs in stateless mode and answers tool calls with plain
  `application/json` instead of a server-sent-events stream. The endpoint only
  exposes tools, so sessions carried no state; idle stateful sessions were never
  cleaned up and could be created without bound, and the SSE responses conflicted
  with the server's write timeout. MCP clients following the Streamable HTTP
  specification are unaffected.
- When an IANA RDAP bootstrap category fails to refresh, it now keeps serving its
  most recent successful fetch (at most one refresh interval stale) instead of
  reverting to the compiled-in baseline from build time. A partial refresh (some
  categories fetched, others failed) is logged as a partial update and recorded as
  `whois_bootstrap_refresh_total{result="partial"}` rather than `success`, and
  `whois_bootstrap_last_fetch_timestamp_seconds` is only advanced on a full
  success.

## [1.0.0] - 2026-06-13

First stable release. From this version on, the HTTP API, error format,
configuration file layout and `WHOIS_*` environment variables are covered by
[Semantic Versioning](https://semver.org/) — see "Versioning & Stability" in
the README. There are no API or configuration-format changes since 0.10.0; the
entries below are operational hardening.

### Security
- The service now logs a startup warning when no `auth.keys` are configured,
  noting that the instance accepts requests from anyone who can reach it (and,
  when `mcp.localhostProtection` is off, that `/mcp` has no DNS-rebinding
  protection). An open instance behind a trusted reverse proxy or on a private
  network is unaffected in behavior; only the warning is new.

### Fixed
- IANA RDAP bootstrap fetches are now capped at 2 MiB, matching the limit
  already applied to WHOIS/RDAP upstream reads; an oversized response is
  rejected instead of read without bound.
- Negative values in numeric configuration settings (`server.port`,
  `server.rateLimit`, `cache.expiration`, `cache.memoryMaxSize`,
  `cache.memoryCleanInterval`, `bootstrap.interval`, `batch.maxItems`) are
  now rejected at startup with a clear error naming the offending key,
  instead of crashing later or silently misbehaving
  (`cache.negativeExpiration` keeps its documented negative "disable"
  semantics).
- `WHOIS_PROXY_SUFFIXES` values are now trimmed of surrounding whitespace and
  empty entries are dropped, matching how `WHOIS_AUTH_KEYS` is parsed; a value
  like `"com, net"` now matches the `net` TLD instead of the unmatchable
  `" net"`.

## [0.10.0] - 2026-06-12

### Added
- **Named API keys with per-key rate limits.** `auth.keys` entries now also
  accept an object form `{key, name, rateLimit}` alongside bare strings
  (fully backward compatible). The name labels the caller in request logs
  (`client` field) and in the new
  `whois_client_requests_total{client, status_code}` Prometheus counter;
  `rateLimit` (requests per minute, token bucket with a full minute's burst)
  answers over-budget requests with an RFC 9457 `429` problem and a
  `Retry-After` header.
- **`POST /batch` bulk queries** (and an MCP `whois_batch_lookup` tool):
  up to `batch.maxItems` (default 10) mixed domain/IP/ASN queries per
  request, each answered independently with per-item status, the regular
  response object in `data` on success and a problem object in `error` on
  failure. Disabled by default (`batch.enabled` / `WHOIS_BATCH_ENABLED`);
  best enabled together with authentication. A batch of N queries costs N
  rate-limit tokens, so batching cannot bypass per-key limits.
- **`?refresh=1` forces a fresh upstream query**, bypassing the cache read
  and overwriting the cached entry (response carries `X-Cache: REFRESH`).
  Only honored on instances with authentication enabled; open instances
  answer `403` (`#refresh-requires-auth`).
- **`WHOIS_BOOTSTRAP_INTERVAL`** environment override (previously the only
  option without one) and a complete environment variable reference table in
  the README (both languages), including an env-only `docker run` example.

## [0.9.0] - 2026-06-11

### Added
- **Optional API key authentication.** A non-empty `auth.keys` list in the
  configuration (or `WHOIS_AUTH_KEYS`, comma-separated) protects every
  endpoint except `/health` and `/ready`. Keys are accepted as
  `Authorization: Bearer <key>` or `X-API-Key: <key>` and compared in
  constant time; failures return an RFC 9457 `401` problem response
  (`#unauthorized`). Authentication is disabled by default.
- **`ETag` and `If-None-Match` conditional requests.** Successful (200)
  responses carry a strong `ETag`; revalidating with `If-None-Match` returns
  `304 Not Modified` with no body. `/openapi.json` supports this too.
- **WHOIS parsers for `.eu` and `.kr`.** EURid domains (`.eu`, `.ею`, `.ευ`)
  and KISA domains (`.kr`, `.한국`) now return parsed fields instead of raw
  WHOIS text. (EURid's port-43 service discloses no dates or status by
  policy; registrar, nameservers and DNSSEC state are what exists.)
- **`secureDNS.keyData`** (RFC 9083 §5.3) for registries that publish DNSKEY
  material instead of DS records (e.g. DENIC).
- Weekly dependabot updates for Go modules and GitHub Actions.

### Fixed
- RDAP: `registrarIanaId` is now taken only from public IDs typed
  `IANA Registrar ID` — `.uk` responses previously returned Nominet's
  registry identifier (`"NOMINET"`) as the IANA ID. Registrar entities are
  also found when nested inside other entities.
- RDAP: DNSSEC is no longer reported unsigned when the registry omits the
  `delegationSigned` boolean but publishes `dsData`/`keyData` (DENIC, among
  others); `dsData` is kept in that case too.
- RDAP: trailing dots stripped from nameserver hostnames (DENIC and Nominet
  return FQDNs like `ns1.denic.de.`).

## [0.8.0] - 2026-06-10

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
- Cache keys moved from `whois:` to `whois:v1:` (the first version of the
  format that will stabilize in 1.0); entries cached by older releases are
  abandoned (no migration needed, they expire naturally).
- **Configuration file restructured.** Keys are grouped by function and use
  camelCase, matching the API field style. Unknown keys and pre-v0.9 keys now
  fail at startup with a migration hint instead of being silently ignored.
  Environment variable names (`WHOIS_*`) are unchanged. Key mapping:

  | Old | New |
  |---|---|
  | `port` | `server.port` |
  | `ratelimit` | `server.rateLimit` |
  | `loglevel` | `log.level` |
  | `cacheexpiration` | `cache.expiration` |
  | `cache.negativecacheexpiration` | `cache.negativeExpiration` |
  | `cache.requireredis` | `cache.requireRedis` |
  | `cache.memorymaxsize` | `cache.memoryMaxSize` |
  | `cache.memorycleaninterval` | `cache.memoryCleanInterval` |
  | `redis.tlsskipverify` | `redis.tlsSkipVerify` |
  | `proxyserver` | `proxy.server` |
  | `proxyusername` | `proxy.username` |
  | `proxypassword` | `proxy.password` |
  | `proxysuffixes` | `proxy.suffixes` |
  | `bootstrapinterval` | `bootstrap.interval` |
  | `mcp.localhostprotection` | `mcp.localhostProtection` |

### Added
- RFC 9082-style typed query paths: `/domain/{name}`, `/ip/{addr}`,
  `/autnum/{asn}` — return 400 when the resource is not of the path's type.
  The auto-detecting root path is unchanged.
- CIDR prefix queries for IP networks, e.g. `/ip/192.0.2.0/24` or
  `/2001:db8::/32` (also via MCP).
- OpenAPI 3.1 description of the service at `/openapi.json`.
- `X-Cache: HIT/MISS` on query responses and
  `Cache-Control: public, max-age=<cache.expiration>` on successful ones.
- CORS: `Access-Control-Allow-Origin: *` on all responses, with preflight
  `OPTIONS` support.
- `cache.expiration` now defaults to 3600 when unset.
- `CHANGELOG.md` (this file) and `SECURITY.md`.
- golangci-lint in CI.

### Changed
- All Go packages moved under `internal/` and renamed to idiomatic Go names
  (`handle_resources`→`handlers`, `server_lists`→`serverlist`,
  `rdap_tools`→`rdap`, `rdap_tools/structs`→`model`, `whois_tools`→`whois`,
  `mcp_server`→`mcp`). No behavior change; the module no longer exposes any
  importable Go API.

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

[1.1.0]: https://github.com/KincaidYang/whois/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/KincaidYang/whois/compare/v0.10.0...v1.0.0
[0.10.0]: https://github.com/KincaidYang/whois/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/KincaidYang/whois/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/KincaidYang/whois/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/KincaidYang/whois/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/KincaidYang/whois/compare/v0.5.4...v0.6.0
