[![Go Reference](https://pkg.go.dev/badge/github.com/KincaidYang/whois.svg)](https://pkg.go.dev/github.com/KincaidYang/whois) [![Go](https://github.com/KincaidYang/whois/actions/workflows/go.yml/badge.svg)](https://github.com/KincaidYang/whois/actions/workflows/go.yml) [![CodeQL](https://github.com/KincaidYang/whois/actions/workflows/codeql.yml/badge.svg)](https://github.com/KincaidYang/whois/actions/workflows/codeql.yml)

[中文文档](README.md)

## Introduction

A domain WHOIS query tool implemented in Golang, supporting WHOIS information queries for all publicly queryable TLD domains, IPv4/v6, and ASN.

In compliance with ICANN's "Temporary Specification for gTLD Registration Data" and the EU's "General Data Protection Regulation" (GDPR), when querying domain information, the program only returns essential information (see response examples below) and does not return the owner's `contact information`, `address`, `phone number`, `email`, and other personal fields.

Demo Sites:
- [https://whois.ddnsip.cn](https://whois.ddnsip.cn)
- [https://whois.mmoke.com](https://whois.mmoke.com/) By [immoke](https://github.com/immoke)

## Usage

### Docker Deployment

```bash
# Install Redis
docker run -d --name redis -p 6379:6379 redis:latest
# Run whois
docker run -d --name whois -p 8043:8043 --link redis:redis jinzeyang/whois
```

### Download

#### Using Binary Files

You can download the binary files for your platform from the [Release](https://github.com/KincaidYang/whois/releases) page.

#### Build from Source

```bash
git clone https://github.com/KincaidYang/whois.git
cd whois
go build
```

### Install Dependencies

This program requires Redis service support. You can refer to https://redis.io/docs/install/install-redis/install-redis-on-linux/ for installation.

### Edit Configuration File

```bash
vim config.yaml
```

> ⚠️ Configuration keys are grouped by function and use **camelCase** (matching the API response field style). Unknown keys and the pre-v0.9 flat keys fail at startup with a migration hint instead of being silently ignored.

```yaml
server:
  port: 8043                   # Server listening port
  rateLimit: 60                # Concurrency limit for upstream WHOIS server requests

log:
  level: "info"                # Log level: debug, info, warn, error (default: info)

cache:
  expiration: 3600             # Cache expiration time in seconds (default: 3600)
  negativeExpiration: 60       # How long "not found / denied" results are cached, in seconds (default: 60; set negative to disable)
  requireRedis: false          # false=allow fallback to memory cache when Redis fails, true=Redis must be available or program exits
  memoryMaxSize: 10000         # Maximum entries in memory cache; least-recently-used entries are evicted past this (default: 10000)
  memoryCleanInterval: 300     # Memory cache cleanup interval in seconds (default: 300)

redis:
  addr: "redis:6379"           # Redis server address
  password: ""                 # Redis password, leave empty if none
  db: 0                        # Redis database number
  tls: false                   # Enable TLS when Redis is reached over an untrusted network
  tlsSkipVerify: false         # Skip certificate verification (not recommended; self-signed certs only)

proxy:
  server: ""                   # Proxy server address; empty disables proxying
  username: ""                 # Proxy server username (if authentication required)
  password: ""                 # Proxy server password (if authentication required)
  suffixes: []                 # TLD suffixes that use the proxy; ["all"] routes everything through the proxy

bootstrap:
  interval: 86400              # RDAP server list refresh interval in seconds; 0 disables fetching (recommended: 86400)

mcp:
  localhostProtection: false   # DNS-rebinding protection for /mcp: only accept requests whose Host header is localhost. Keep false behind a reverse proxy; set true for direct localhost deployments
```

Selected options can be overridden via environment variables (which take precedence over the config file), e.g. `WHOIS_REDIS_ADDR`, `WHOIS_REDIS_TLS`, `WHOIS_PORT`, `WHOIS_RATE_LIMIT`, `WHOIS_CACHE_EXPIRATION`, `WHOIS_NEGATIVE_CACHE_EXPIRATION`, `WHOIS_LOG_LEVEL`, `WHOIS_MCP_LOCALHOST_PROTECTION`.

**Configuration Notes:**
- **Redis Configuration**: Redis is recommended for better performance and multi-instance cache sharing
- **Cache Expiration**: Adjust based on query frequency, 3600 seconds recommended
- **Memory Cache**: Fallback when Redis is unavailable; evicts least-recently-used (LRU) entries once full
- **Negative Cache**: Briefly caches "not found / denied" results to avoid repeatedly hitting upstream for missing resources; defaults to 60 seconds
- **Concurrency Limit**: Controls request frequency to upstream servers to avoid rate limiting
- **Proxy Configuration**: Some TLDs may require proxy access
- **Log Level**: `debug` logs every cache hit and upstream query dispatch — noisy under load; `info` is recommended for production
- **Bootstrap Interval**: On startup the service immediately fetches the latest RDAP server list from IANA, then refreshes on this interval; compiled-in data serves as fallback if the fetch fails

> ⚠️ **Warning:** The rate limit applies to requests from this program to WHOIS servers, not requests from users to this program. For example, if you set the limit to 50, the program will not exceed 50 requests/second to registry WHOIS servers, but user requests to this program are unlimited. Please use Nginx or other tools to rate-limit this program to prevent malicious requests.

### Run

```bash
./whois
```

**Note:** The program listens on port 8043 by default.

### Health Check Endpoints

The service provides the following health check endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Liveness probe - returns 200 if service is running |
| `GET /ready` | Readiness probe - checks cache and capacity status |
| `GET /info` | Runtime information - version, uptime, Go version, etc. |
| `GET /metrics` | Prometheus metrics - request count, latency, cache hit rate, upstream query duration |
| `POST /mcp` | MCP Streamable HTTP endpoint - for AI assistant integration |

### Process Daemon (Optional)

You can use systemd or other tools to set up this program as a daemon process to auto-start after system reboot.

```bash
vim /etc/systemd/system/whois.service
```

```ini
[Unit]
Description=whois
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
ExecStart=/path/to/whois/whois
WorkingDirectory=/path/to/whois
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### API Usage

GET requests

#### Browser Access

After deployment, access `http://ip:port/domain-or-ip-or-asn` via browser. Default port is `8043`, e.g., `http://1.2.3.4:8043/example.com`

#### Typed Query Paths

Besides the auto-detecting root path, [RFC 9082](https://www.rfc-editor.org/rfc/rfc9082)-style typed paths are available, suited to programmatic use — a resource of the wrong type returns 400 instead of being interpreted as another type:

```bash
curl http://localhost:8043/domain/example.com
curl http://localhost:8043/ip/192.0.2.1
curl http://localhost:8043/autnum/205794    # as205794 / AS205794 also accepted
```

#### Caching and CORS

- Successful responses carry `X-Cache: HIT/MISS` indicating whether the server cache was hit, plus `Cache-Control: public, max-age=<cache seconds>` for client/CDN caching.
- Every response carries `Access-Control-Allow-Origin: *`, so the API can be called cross-origin from browser frontends directly.

> Internationalized domain names (IDN, including Unicode domains with non-ASCII characters) can be queried directly; the program converts them to Punycode automatically, e.g. `http://1.2.3.4:8043/例子.cn`.

#### Query Domain WHOIS Information

```bash
curl http://localhost:8043/example.com
```

Response:
```json
{
  "objectClassName": "domain",
  "ldhName": "example.com",
  "registrar": "RESERVED-Internet Assigned Numbers Authority",
  "registrarIanaId": "376",
  "status": [
    "client delete prohibited",
    "client transfer prohibited",
    "client update prohibited"
  ],
  "registrationDate": "1995-08-14T04:00:00Z",
  "expirationDate": "2026-08-13T04:00:00Z",
  "lastChangedDate": "2025-08-14T07:01:34Z",
  "nameservers": [
    "a.iana-servers.net",
    "b.iana-servers.net"
  ],
  "secureDNS": {
    "delegationSigned": true,
    "dsData": [
      {
        "keyTag": 370,
        "algorithm": 13,
        "digestType": 2,
        "digest": "BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C"
      }
    ]
  },
  "lastUpdateOfRdapDb": "2026-01-16T10:26:40Z"
}
```

Field names and vocabulary follow [RDAP (RFC 9083)](https://www.rfc-editor.org/rfc/rfc9083): `objectClassName` identifies the object type (`domain` / `ip network` / `autnum`), and dates are normalized to RFC 3339 UTC. IDN domains additionally include a `unicodeName` field. For ccTLDs without a parser, the response is `{"objectClassName": "domain", "unparsed": true, "rawText": "..."}`.

#### Query Raw WHOIS Text for a Domain

Add `?raw=1` to get the unparsed WHOIS response as `text/plain`. Raw output is only supported for domain queries (IP/ASN lookups use RDAP, which has no raw-text form). Raw queries go straight to the WHOIS server (skipping RDAP) and return 404 when no WHOIS server is known for the TLD.

```bash
curl "http://localhost:8043/example.com?raw=1"
```

#### Request Tracing

Every response carries an `X-Request-ID` header that matches the `request_id` field in server logs, making it easy to correlate a request with its log lines. Clients may also supply their own `X-Request-ID` header (max 64 characters, limited to letters, digits, `.`, `_`, `-`), which the server will reuse as-is.

#### Query IPv4 WHOIS Information

```bash
curl http://localhost:8043/1.12.34.56
```

Response:
```json
{
  "objectClassName": "ip network",
  "handle": "1.12.0.0 - 1.15.255.255",
  "startAddress": "1.12.0.0",
  "endAddress": "1.15.255.255",
  "cidr": "1.12.0.0/14",
  "name": "TencentCloud",
  "type": "ALLOCATED PORTABLE",
  "country": "CN",
  "status": ["active"],
  "registrationDate": "2010-05-10T22:46:58Z",
  "lastChangedDate": "2023-11-28T00:51:33Z"
}
```

#### Query IPv6 WHOIS Information

```bash
curl http://localhost:8043/2402:4e00::
```

Response:
```json
{
  "objectClassName": "ip network",
  "handle": "2402:4e00::/32",
  "startAddress": "2402:4e00::",
  "endAddress": "2402:4e00:ffff:ffff:ffff:ffff:ffff:ffff",
  "cidr": "2402:4e00::/32",
  "name": "TencentCloud",
  "type": "ALLOCATED PORTABLE",
  "country": "CN",
  "status": ["active"],
  "registrationDate": "2010-05-12T23:13:32Z",
  "lastChangedDate": "2024-01-31T06:27:10Z"
}
```

#### Query ASN WHOIS Information

```bash
curl http://localhost:8043/ASN205794
curl http://localhost:8043/AS205794
curl http://localhost:8043/205794
```

⚠ Case-insensitive

Response:
```json
{
  "objectClassName": "autnum",
  "handle": "AS205794",
  "name": "RTTW-AS",
  "status": ["active"],
  "registrationDate": "2022-04-14T12:24:55Z",
  "lastChangedDate": "2024-03-21T07:27:44Z",
  "remarks": [
    {
      "title": "",
      "description": [
        "https://as205794.net/",
        "Geofeed https://geo.as205794.net/geofeed.csv",
        "Looking Glass https://lg.as205794.net/"
      ]
    }
  ]
}
```

#### Error Responses

Error responses follow [RFC 9457 Problem Details](https://www.rfc-editor.org/rfc/rfc9457) with `Content-Type: application/problem+json`:

```json
{
  "type": "https://github.com/KincaidYang/whois/blob/main/docs/errors.md#not-found",
  "title": "Resource not found",
  "status": 404
}
```

See [docs/errors.md](docs/errors.md) for the full list of problem types.

### MCP Integration

The service exposes an [MCP (Model Context Protocol)](https://modelcontextprotocol.io) endpoint at `/mcp` using the Streamable HTTP transport, allowing AI assistants (e.g. Claude) to call WHOIS lookups as a tool.

**Tool:** `whois_lookup`

**Input:**
```json
{ "query": "example.com" }
```

Accepts a domain name, IPv4/v6 address, or ASN (e.g. `AS12345`). Returns the same JSON as the REST API.

**MCP server URL:** `http://ip:port/mcp`

## Known Issues

The program queries WHOIS information from registries primarily using the RDAP protocol. However, since most ccTLDs do not support RDAP, the program will format and return the original WHOIS information as JSON data. Due to limited resources, not all ccTLD suffixes have been adapted; unadapted suffixes return `{"objectClassName": "domain", "unparsed": true, "rawText": "..."}`. If your commonly used suffix is not covered, please submit an Issue or contribute matching rules to `internal/whois/whois_parsers.go`. Thank you!

## Dependencies

This project uses the following Go standard libraries:

- [`bytes`](https://golang.org/pkg/bytes/): Functions for byte slice operations
- [`context`](https://golang.org/pkg/context/): Context type for passing deadlines, cancellation signals, and request-scoped values
- [`encoding/json`](https://golang.org/pkg/encoding/json/): JSON encoding and decoding
- [`errors`](https://golang.org/pkg/errors/): Error creation and manipulation
- [`fmt`](https://golang.org/pkg/fmt/): Formatted I/O functions
- [`io`](https://golang.org/pkg/io/): I/O primitives
- [`log/slog`](https://golang.org/pkg/log/slog/): Structured logging
- [`net`](https://golang.org/pkg/net/): Network I/O primitives
- [`net/http`](https://golang.org/pkg/net/http/): HTTP client and server implementation
- [`os`](https://golang.org/pkg/os/): OS functionality
- [`os/signal`](https://golang.org/pkg/os/signal/): OS signal handling
- [`regexp`](https://golang.org/pkg/regexp/): Regular expression search
- [`strconv`](https://golang.org/pkg/strconv/): String conversion functions
- [`strings`](https://golang.org/pkg/strings/): String manipulation functions
- [`sync`](https://golang.org/pkg/sync/): Basic synchronization primitives
- [`syscall`](https://golang.org/pkg/syscall/): Low-level OS calls
- [`time`](https://golang.org/pkg/time/): Time measurement and display

This project also uses the following third-party libraries:

- [`github.com/redis/go-redis/v9`](https://github.com/go-redis/redis): Redis client for Go
- [`github.com/prometheus/client_golang`](https://github.com/prometheus/client_golang): Prometheus metrics instrumentation and exposition
- [`github.com/modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk): MCP (Model Context Protocol) Go SDK
- [`golang.org/x/net/idna`](https://pkg.go.dev/golang.org/x/net/idna): IDNA (Internationalized Domain Names in Applications) implementation
- [`golang.org/x/net/publicsuffix`](https://pkg.go.dev/golang.org/x/net/publicsuffix): Public Suffix List implementation
- [`gopkg.in/yaml.v3`](https://gopkg.in/yaml.v3): YAML parsing library

WHOIS/RDAP server lists are sourced from:
- [IANA](https://www.iana.org/domains/root/db)
- [IANA RDAP Bootstrap](https://data.iana.org/rdap/)
- [IANA RDAP Bootstrap (IPv4)](https://data.iana.org/rdap/ipv4.json)
- [IANA RDAP Bootstrap (IPv6)](https://data.iana.org/rdap/ipv6.json)
- [IANA RDAP Bootstrap (AS)](https://data.iana.org/rdap/asn.json)

## License

[MIT License](LICENSE)
