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

```yaml
redis:
  addr: "redis:6379"           # Redis server address
  password: ""                 # Redis password, leave empty if none
  db: 0                        # Redis database number
cacheExpiration: 3600          # Cache expiration time in seconds

# Advanced cache configuration (optional, new feature)
cache:
  requireRedis: false          # false=allow fallback to memory cache when Redis fails, true=Redis must be available or program exits
  memoryMaxSize: 10000         # Maximum entries in memory cache (default: 10000)
  memoryCleanInterval: 300     # Memory cache cleanup interval in seconds (default: 300)

port: 8043                     # Server listening port
rateLimit: 50                  # Concurrency limit for upstream WHOIS server requests

# Proxy configuration (optional)
ProxyServer: "http://127.0.0.1:8080"  # Proxy server address
ProxySuffixes:                         # TLD suffixes that need proxy, leave empty to disable
ProxyUsername: ""                      # Proxy server username (if authentication required)
ProxyPassword: ""                      # Proxy server password (if authentication required)
```

**Configuration Notes:**
- **Redis Configuration**: Redis is recommended for better performance and multi-instance cache sharing
- **Cache Expiration**: Adjust based on query frequency, 3600 seconds recommended
- **Concurrency Limit**: Controls request frequency to upstream servers to avoid rate limiting
- **Proxy Configuration**: Some TLDs may require proxy access

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

#### Query Domain WHOIS Information

```bash
curl http://localhost:8043/example.com
```

Response:
```json
{
    "Domain Name": "EXAMPLE.COM",
    "Registrar": "RESERVED-Internet Assigned Numbers Authority",
    "Registrar IANA ID": "376",
    "Domain Status": [
        "client delete prohibited",
        "client transfer prohibited",
        "client update prohibited"
    ],
    "Creation Date": "1995-08-14T04:00:00Z",
    "Registry Expiry Date": "2024-08-13T04:00:00Z",
    "Updated Date": "2023-08-14T07:01:38Z",
    "Name Server": [
        "A.IANA-SERVERS.NET",
        "B.IANA-SERVERS.NET"
    ],
    "DNSSEC": "signedDelegation",
    "DNSSEC DS Data": "370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C",
    "Last Update of Database": "2024-01-16T10:26:40Z"
}
```

#### Query IPv4 WHOIS Information

```bash
curl http://localhost:8043/1.12.34.56
```

Response:
```json
{
  "IP Network": "1.12.0.0 - 1.15.255.255",
  "Address Range": "1.12.0.0 - 1.15.255.255",
  "Network Name": "TencentCloud",
  "CIDR": "1.12.0.0/14",
  "Network Type": "ALLOCATED PORTABLE",
  "Country": "CN",
  "Status": ["active"],
  "Creation Date": "2010-05-10T22:46:58Z",
  "Updated Date": "2023-11-28T00:51:33Z"
}
```

#### Query IPv6 WHOIS Information

```bash
curl http://localhost:8043/2402:4e00::
```

Response:
```json
{
  "IP Network": "2402:4e00::/32",
  "Address Range": "2402:4e00:: - 2402:4e00:ffff:ffff:ffff:ffff:ffff:ffff",
  "Network Name": "TencentCloud",
  "CIDR": "2402:4e00::/32",
  "Network Type": "ALLOCATED PORTABLE",
  "Country": "CN",
  "Status": ["active"],
  "Creation Date": "2010-05-12T23:13:32Z",
  "Updated Date": "2024-01-31T06:27:10Z"
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
  "AS Number": "AS205794",
  "Network Name": "RTTW-AS",
  "Status": ["active"],
  "Creation Date": "2022-04-14T12:24:55Z",
  "Updated Date": "2024-03-21T07:27:44Z",
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

## Known Issues

The program queries WHOIS information from registries primarily using the RDAP protocol. However, since most ccTLDs do not support RDAP, the program will format and return the original WHOIS information as JSON data. Due to limited resources, not all ccTLD suffixes have been adapted, and the program may directly return `text` data. If your commonly used suffix is not covered, please submit an Issue or contribute matching rules to the `whois_parsers.go` file. Thank you!

You can determine the response data format by checking the `content-type` header.

## Dependencies

This project uses the following Go standard libraries:

- [`bytes`](https://golang.org/pkg/bytes/): Functions for byte slice operations
- [`context`](https://golang.org/pkg/context/): Context type for passing deadlines, cancellation signals, and request-scoped values
- [`encoding/json`](https://golang.org/pkg/encoding/json/): JSON encoding and decoding
- [`errors`](https://golang.org/pkg/errors/): Error creation and manipulation
- [`fmt`](https://golang.org/pkg/fmt/): Formatted I/O functions
- [`io`](https://golang.org/pkg/io/): I/O primitives
- [`log`](https://golang.org/pkg/log/): Simple logging service
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
