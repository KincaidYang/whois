[![Go Reference](https://pkg.go.dev/badge/github.com/KincaidYang/whois.svg)](https://pkg.go.dev/github.com/KincaidYang/whois) [![Go](https://github.com/KincaidYang/whois/actions/workflows/go.yml/badge.svg)](https://github.com/KincaidYang/whois/actions/workflows/go.yml) [![CodeQL](https://github.com/KincaidYang/whois/actions/workflows/codeql.yml/badge.svg)](https://github.com/KincaidYang/whois/actions/workflows/codeql.yml) [![codecov](https://codecov.io/gh/KincaidYang/whois/graph/badge.svg)](https://codecov.io/gh/KincaidYang/whois)

[English](README_EN.md)

## 介绍
基于 Golang 实现的域名 Whois 查询工具，支持所有允许公开查询的 TLD 后缀的域名、IPv4/v6、ASN 的 Whois 信息查询。
根据 ICANN 《通用顶级域名注册数据临时政策细则（Temporary Specification for gTLD Registration Data）》和欧盟《通用数据保护条例》合规要求，在查询域名信息时，程序只返回了部分必要的信息（详见下方返回结果示例），不会返回所有者的`联系方式`、`地址`、`电话`、`邮箱`等字段。

演示站点：
- [https://whois.ddnsip.cn](https://whois.ddnsip.cn)
- [https://whois.mmoke.com](https://whois.mmoke.com/) By [immoke](https://github.com/immoke)

## 使用方法
### Docker部署
```bash
# 安装 Redis
docker run -d --name redis -p 6379:6379 redis:latest
# 运行 whois
docker run -d --name whois -p 8043:8043 --link redis:redis jinzeyang/whois
# 运行 whois（大陆推荐）
docker run -d --name whois -p 8043:8043 --link redis:redis docker.cnb.cool/kincaidyang/whois
```

### 下载
#### 使用二进制文件
您可从 [Release](https://github.com/KincaidYang/whois/releases) 页面下载对应平台的二进制文件。
#### 从源码编译
```bash
git clone https://github.com/KincaidYang/whois.git
cd whois
go build
```
### 安装依赖
本程序默认使用内存缓存，可直接运行；生产环境或多实例部署建议搭配 Redis 使用，您可参照 https://redis.io/docs/install/install-redis/install-redis-on-linux/ 进行安装。

### 编辑配置文件
```bash
vim config.yaml
```
> ⚠️ 配置项按功能分组，键名为 **camelCase**（与 API 响应字段风格一致）。未知键或旧版（v0.9 之前）的扁平键会在启动时报错并给出迁移提示，不会再静默回退到默认值。

```yaml
server:
  port: 8043                   # 服务监听端口
  rateLimit: 60                # 并发限制，即程序向上游whois服务器发起的最大并发请求数

log:
  level: "info"                # 日志级别：debug、info、warn、error（默认：info）

cache:
  expiration: 3600             # 缓存过期时间，单位：秒（默认：3600）
  negativeExpiration: 60       # “未找到/被拒”结果的缓存时间，单位：秒（默认: 60；设为负数则禁用）
  requireRedis: false          # false=允许Redis失败时降级到内存缓存，true=Redis必须可用否则程序退出
  memoryMaxSize: 10000         # 内存缓存最大条目数，超过此数量按 LRU 淘汰最久未使用条目（默认: 10000）
  memoryCleanInterval: 300     # 内存缓存过期数据清理间隔，单位：秒（默认: 300）

redis:
  addr: "redis:6379"           # Redis服务器地址
  password: ""                 # Redis密码，如无密码则留空
  db: 0                        # Redis数据库编号
  tls: false                   # 通过不可信网络连接 Redis 时建议开启 TLS
  tlsSkipVerify: false         # 跳过证书校验（不推荐，仅自签名证书场景使用）

proxy:
  server: ""                   # 代理服务器地址，留空表示不使用代理
  username: ""                 # 代理服务器用户名（如需认证）
  password: ""                 # 代理服务器密码（如需认证）
  suffixes: []                 # 需要使用代理的TLD后缀列表；填 ["all"] 表示全部走代理

bootstrap:
  interval: 86400              # RDAP 服务器列表从 IANA 刷新间隔，单位：秒；0 则禁用（推荐：86400）

auth:
  keys: []                     # API 密钥列表。留空（默认）则服务完全开放；配置一个或多个密钥后，除 /health 和 /ready 外的所有端点都需要认证，请求时通过 "Authorization: Bearer <key>" 或 "X-API-Key: <key>" 携带密钥
  # 列表项支持纯字符串，也支持对象形式（可命名、可按 key 限流）：
  # keys:
  #   - "plain-secret"         # 匿名 key，自动命名 key1/key2/…
  #   - key: "another-secret"
  #     name: "ci"             # 显示名：出现在日志 client 字段和 Prometheus 指标中
  #     rateLimit: 120         # 该 key 的速率限制（次/分钟）；0 或缺省=不限

batch:
  enabled: false               # POST /batch 批量查询端点（含 MCP 批量 tool），默认关闭；建议与 auth.keys 一起开启
  maxItems: 10                 # 单批最多查询条数

mcp:
  localhostProtection: false   # /mcp 端点的 DNS rebinding 保护：开启后只接受 Host 为 localhost 的请求。反向代理部署保持 false；本机直连部署建议设为 true
```

### 环境变量

所有配置项均可通过环境变量覆盖（优先级高于配置文件），适合 Docker/Kubernetes 等不便挂载配置文件的部署方式：

| 环境变量 | 对应配置项 | 默认值 | 说明 |
|---------|-----------|--------|------|
| `WHOIS_PORT` | `server.port` | `8043` | 服务监听端口 |
| `WHOIS_RATE_LIMIT` | `server.rateLimit` | `100` | 最大并发请求数 |
| `WHOIS_LOG_LEVEL` | `log.level` | `info` | 日志级别：debug、info、warn、error |
| `WHOIS_CACHE_EXPIRATION` | `cache.expiration` | `3600` | 缓存过期时间（秒） |
| `WHOIS_NEGATIVE_CACHE_EXPIRATION` | `cache.negativeExpiration` | `60` | 负向缓存时间（秒），负数禁用 |
| `WHOIS_REQUIRE_REDIS` | `cache.requireRedis` | `false` | `true`/`1` 时 Redis 不可用则启动失败 |
| `WHOIS_MEMORY_MAX_SIZE` | `cache.memoryMaxSize` | `10000` | 内存缓存最大条目数 |
| `WHOIS_MEMORY_CLEAN_INTERVAL` | `cache.memoryCleanInterval` | `300` | 内存缓存清理间隔（秒） |
| `WHOIS_REDIS_ADDR` | `redis.addr` | 未设置 | Redis 地址；显式设为空（`WHOIS_REDIS_ADDR=`）则禁用 Redis 仅用内存缓存，配置后不可用时自动降级到内存缓存（除非开启 requireRedis） |
| `WHOIS_REDIS_PASSWORD` | `redis.password` | 空 | Redis 密码 |
| `WHOIS_REDIS_DB` | `redis.db` | `0` | Redis 数据库编号 |
| `WHOIS_REDIS_TLS` | `redis.tls` | `false` | `true`/`1` 启用 Redis TLS |
| `WHOIS_REDIS_TLS_SKIP_VERIFY` | `redis.tlsSkipVerify` | `false` | `true`/`1` 跳过证书校验（不推荐） |
| `WHOIS_PROXY_SERVER` | `proxy.server` | 空 | 代理服务器地址，空则不使用代理 |
| `WHOIS_PROXY_USERNAME` | `proxy.username` | 空 | 代理用户名 |
| `WHOIS_PROXY_PASSWORD` | `proxy.password` | 空 | 代理密码 |
| `WHOIS_PROXY_SUFFIXES` | `proxy.suffixes` | 空 | 走代理的 TLD 列表，**逗号分隔**（`all` 表示全部） |
| `WHOIS_BOOTSTRAP_INTERVAL` | `bootstrap.interval` | `0`（禁用） | IANA RDAP 列表刷新间隔（秒）；配置文件示例为 86400 |
| `WHOIS_AUTH_KEYS` | `auth.keys` | 空 | API 密钥，**逗号分隔**（仅纯 key 形式；命名/按 key 限流需配置文件） |
| `WHOIS_BATCH_ENABLED` | `batch.enabled` | `false` | `true`/`1` 开启批量查询端点 |
| `WHOIS_BATCH_MAX_ITEMS` | `batch.maxItems` | `10` | 单批最多查询条数 |
| `WHOIS_MCP_LOCALHOST_PROTECTION` | `mcp.localhostProtection` | `false` | `true`/`1` 启用 /mcp 的 DNS rebinding 保护 |

布尔型变量只认 `true` 和 `1`，其余值视为 `false`。数值型变量解析失败时静默忽略并沿用配置文件/默认值。

纯环境变量部署示例（不挂载配置文件）：

```bash
docker run -d --name whois -p 8043:8043 \
  -e WHOIS_REDIS_ADDR=redis:6379 \
  -e WHOIS_BOOTSTRAP_INTERVAL=86400 \
  -e WHOIS_AUTH_KEYS=secret1,secret2 \
  --link redis:redis jinzeyang/whois
```

**配置说明：**
- **Redis配置**：建议使用Redis以获得更好的性能和多实例缓存共享能力
- **缓存过期时间**：根据查询频率调整，建议3600秒
- **内存缓存**：Redis 不可用时的兜底，达到上限后按 LRU（最近最少使用）淘汰
- **负向缓存**：将“未找到/被拒”的查询结果短时间缓存，避免对不存在的资源反复请求上游；默认 60 秒
- **并发限制**：控制向上游服务器的请求频率，避免被限流。
- **代理配置**：某些TLD可能需要代理访问，可配置特定后缀使用代理
- **日志级别**：`debug` 会输出每次缓存命中和上游查询，流量大时噪声较高；生产环境建议保持 `info`
- **RDAP 刷新间隔**：服务启动时会立即从 IANA 拉取最新 RDAP 服务器列表，之后按此间隔定期刷新；编译进二进制的数据作为拉取失败时的兜底
- **API 认证**：默认关闭。配置 `auth.keys` 后即启用，未携带有效密钥的请求返回 401（RFC 9457 problem+json）；仅 `/health` 和 `/ready` 豁免，便于存活/就绪探针工作
- **key 命名与按 key 限流**：`auth.keys` 的对象形式可为每个 key 设置显示名和速率限制。显示名出现在请求日志的 `client` 字段和 Prometheus 指标 `whois_client_requests_total{client,status_code}` 中，便于区分调用方；速率限制为 token bucket（次/分钟，**允许一次性用完整分钟额度**），超限返回 429 + `Retry-After` 头。批量查询按条数计入额度：一批 N 条消耗 N 个请求额度
- **批量查询**：默认关闭。建议与 `auth.keys` 一起开启——开放实例提供批量查询等于放大被滥用打上游注册局的能力


> ⚠️ **Warning:** 限频针对的是程序向 whois 服务器发起的请求，而非用户向本程序发起的请求。例如，您将限频设置为 50，那么程序向注册局 whois 服务器发起的请求将不会超过 50 次/秒，但是用户向本程序发起的请求不受限制。请您通过 Nginx 等工具对本程序进行限流，或为每个 API key 配置 `rateLimit`，以防止恶意请求。

### 运行
```bash
./whois
```
**注意：** 本程序默认监听 8043 端口。

### 健康检查端点

服务提供以下健康检查端点：

| 端点 | 描述 |
|------|------|
| `GET /health` | 存活检查 - 服务运行即返回 200 |
| `GET /ready` | 就绪检查 - 检查缓存和并发容量状态 |
| `GET /info` | 运行时信息 - 版本、运行时间、Go 版本等 |
| `GET /metrics` | Prometheus 指标 - 请求计数、延迟、缓存命中率、上游查询耗时 |
| `GET /openapi.json` | OpenAPI 3.1 规范 - 全部端点与响应 schema 的机器可读描述 |
| `POST /mcp` | MCP Streamable HTTP 端点 - 供 AI 助手集成使用 |
| `POST /batch` | 批量查询 - 一次提交多个域名/IP/ASN（默认关闭，见 `batch.enabled`） |

**示例：**
```bash
curl http://localhost:8043/health
```
```json
{
  "status": "ok",
  "timestamp": "2026-02-05T01:32:05Z",
  "uptime": "10s",
  "checks": {
    "cache": {"status": "ok", "message": "redis"}
  }
}
```

### 进程守护（可选）
您可以使用 systemd 等工具将本程序设置为守护进程，以便在系统重启后自动运行。
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
### 使用
GET 请求

#### 浏览器访问
部署后直接通过浏览器访问`http://ip:端口/你想查的域名或ip或asn`，默认端口`8043`，示例`http://1.2.3.4:8043/examlpe.com`,详细示例请参考下方

> 支持直接查询国际化域名（IDN，含中文、带变音符号等 Unicode 域名），程序会自动转换为 Punycode 后查询，例如 `http://1.2.3.4:8043/例子.cn`。

#### 类型化查询路径
除根路径自动识别外，还提供 [RFC 9082](https://www.rfc-editor.org/rfc/rfc9082) 风格的类型化路径，适合程序化调用——资源类型不匹配时直接返回 400，不会被识别成其他类型：

```bash
curl http://localhost:8043/domain/example.com
curl http://localhost:8043/ip/192.0.2.1
curl http://localhost:8043/autnum/205794    # 也接受 as205794 / AS205794
```

IP 查询支持 **CIDR 前缀**（根路径和 `/ip/` 均可）：

```bash
curl http://localhost:8043/ip/192.0.2.0/24
curl http://localhost:8043/2001:db8::/32
```

#### OpenAPI 规范
服务在 `/openapi.json` 提供 OpenAPI 3.1 描述文档，包含全部端点、响应 schema（RDAP 词汇）和错误格式，可直接导入 Postman/Swagger UI 等工具。

#### 缓存与跨域
- 成功响应带 `X-Cache` 头标识缓存状态：`HIT`（命中服务端缓存）、`MISS`（回源注册局）、`REFRESH`（`?refresh` 强制回源），以及 `Cache-Control: public, max-age=<缓存秒数>` 供客户端/CDN 缓存。
- 成功响应（200）带强 `ETag` 头；请求时携带 `If-None-Match: <etag>` 可做条件重验证，内容未变化时返回 `304 Not Modified`（无响应体），`/openapi.json` 同样支持。
- 所有响应带 `Access-Control-Allow-Origin: *`，可直接在浏览器前端跨域调用。

#### 查询域名 Whois 信息
```bash
curl http://localhost:8043/example.com
```
返回结果
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

字段名与词汇遵循 [RDAP（RFC 9083）](https://www.rfc-editor.org/rfc/rfc9083)规范：`objectClassName` 标识对象类型（`domain` / `ip network` / `autnum`），日期统一为 RFC 3339 UTC 格式。查询 IDN 域名时会额外返回 `unicodeName` 字段。对于无法解析的 ccTLD，返回 `{"objectClassName": "domain", "unparsed": true, "rawText": "..."}`。

#### 查询域名原始 WHOIS 文本
添加 `?raw=1` 参数可获取未解析的 WHOIS 原文（`text/plain`），仅支持域名查询（IP/ASN 走 RDAP，无原文形式）。原文查询直接访问 WHOIS 服务器（跳过 RDAP），若该 TLD 没有已知 WHOIS 服务器则返回 404。

```bash
curl "http://localhost:8043/example.com?raw=1"
```

#### 强制刷新缓存
添加 `?refresh=1` 参数可跳过服务端缓存、强制向注册局查询并用新结果覆盖缓存（响应带 `X-Cache: REFRESH`），适合域名转移/续费后立即查看新状态。**仅在开启 API 认证的实例上可用**：未配置 `auth.keys` 的实例返回 403（`refresh-requires-auth`）——否则任何人都能借此击穿缓存刷上游注册局。可与 `?raw` 叠加使用。

```bash
curl -H "X-API-Key: your-secret-key" "http://localhost:8043/example.com?refresh=1"
```

#### 批量查询
`POST /batch` 一次提交多个查询（域名/IP/CIDR/ASN 可混排，自动识别类型），逐项返回结果。默认关闭，需配置 `batch.enabled: true`；单批条数上限 `batch.maxItems`（默认 10）。

```bash
curl -X POST -H "X-API-Key: your-secret-key" -H "Content-Type: application/json" \
  -d '{"queries": ["example.com", "8.8.8.8", "AS15169"]}' \
  http://localhost:8043/batch
```

响应恒为 200，逐项给出状态：成功项的 `data` 是常规响应对象，失败项的 `error` 是 problem+json 对象：

```json
{
  "results": [
    {"query": "example.com", "status": 200, "data": {"objectClassName": "domain", "ldhName": "example.com"}},
    {"query": "nx.invalid", "status": 404, "error": {"type": "...#not-found", "title": "Resource not found", "status": 404}}
  ]
}
```

配置了按 key 限流时，一批 N 条会消耗 N 个请求额度，无法借批量绕过限流。批内重复查询会被合并为一次上游请求。

#### 请求追踪
每个响应都带有 `X-Request-ID` 头，服务端日志中的 `request_id` 字段与之对应，便于排查问题。客户端也可自带 `X-Request-ID` 请求头（≤64 字符，仅限字母、数字、`.`、`_`、`-`），服务端将原样使用。

#### 查询 IPv4 Whois 信息
```bash
curl http://localhost:8043/1.12.34.56
```
返回结果
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
  "status": [
    "active"
  ],
  "registrationDate": "2010-05-10T22:46:58Z",
  "lastChangedDate": "2023-11-28T00:51:33Z",
  "remarks": [
    {
      "title": "description",
      "description": [
        "Tencent cloud computing (Beijing) Co., Ltd.",
        "Floor 6, Yinke Building,38 Haidian St,",
        "Haidian District Beijing"
      ]
    }
  ]
}
```

#### 查询 IPv6 Whois 信息
```bash
curl http://localhost:8043/2402:4e00::
```
返回结果
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
  "status": [
    "active"
  ],
  "registrationDate": "2010-05-12T23:13:32Z",
  "lastChangedDate": "2024-01-31T06:27:10Z",
  "remarks": [
    {
      "title": "description",
      "description": [
        "Tencent cloud computing (Beijing) Co., Ltd.",
        "Floor 6, Yinke Building,38 Haidian St,Haidian District Beijing"
      ]
    }
  ]
}
```

#### 查询 ASN Whois 信息
```bash
curl http://localhost:8043/ASN205794
curl http://localhost:8043/AS205794
curl http://localhost:8043/205794
```
⚠ 不区分大小写

返回结果
```json
{
  "objectClassName": "autnum",
  "handle": "AS205794",
  "name": "RTTW-AS",
  "status": [
    "active"
  ],
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

#### 错误响应
错误响应遵循 [RFC 9457 Problem Details](https://www.rfc-editor.org/rfc/rfc9457) 规范，`Content-Type` 为 `application/problem+json`：

```json
{
  "type": "https://github.com/KincaidYang/whois/blob/main/docs/errors.md#not-found",
  "title": "Resource not found",
  "status": 404
}
```

全部错误类型见 [docs/errors.md](docs/errors.md)。

### MCP 集成

服务在 `/mcp` 提供 [MCP（Model Context Protocol）](https://modelcontextprotocol.io) 端点，使用 Streamable HTTP 传输，支持 AI 助手（如 Claude）将 WHOIS 查询作为工具直接调用。

**工具名：** `whois_lookup`

**输入：**
```json
{ "query": "example.com" }
```

支持域名、IPv4/v6 地址或 CIDR 前缀、ASN（如 `AS12345`），返回结果与 REST API 完全一致。

**工具名：** `whois_batch_lookup`（需开启 `batch.enabled`）

**输入：**
```json
{ "queries": ["example.com", "8.8.8.8", "AS15169"] }
```

逐项返回结果，与 `POST /batch` 行为一致（同样受 `batch.maxItems` 与按 key 限流约束）。

**MCP 服务器地址：** `http://ip:端口/mcp`

客户端接入配置与认证方式见 [docs/mcp.md](docs/mcp.md)。

## 版本与稳定性

自 v1.0.0 起，本项目遵循[语义化版本](https://semver.org/lang/zh-CN/)。以下面向用户的契约在 1.x 内保持稳定，不兼容变更只会出现在下一个主版本（2.0.0）：

- **HTTP API**：端点路径与语义、成功响应的 JSON 字段（RDAP 词汇，RFC 9083）、错误格式（RFC 9457 problem+json），以及缓存与条件请求相关的响应头（`X-Cache`、`Cache-Control`、`ETag`）。
- **配置文件**：`config.yaml` 的分组结构与键名，以及 `WHOIS_*` 环境变量。
- **MCP 工具**：`whois_lookup` / `whois_batch_lookup` 的名称与输入参数。

不在稳定承诺范围内：注册局上游数据本身的内容与可用字段（随各注册局而变）、Prometheus 指标名称、日志格式，以及 Go 包的内部结构（本模块不对外暴露可导入的 API）。

0.x 阶段的破坏性变更已结束，完整历史见 [CHANGELOG](CHANGELOG.md)。

## 已知问题
程序向注册局查询 Whois 信息主要依靠 RDAP 协议查询，但由于大部分 ccTLD 不支持 RDAP 协议，程序会对其原始的 Whois 信息格式化后返回 JSON 数据。由于本人精力有限，未对所有的 ccTLD 后缀进行适配，未适配的后缀会返回 `{"objectClassName": "domain", "unparsed": true, "rawText": "..."}`，如您常用的后缀没有被覆盖，可以提交 Issue 或者贡献匹配规则至 `internal/whois/whois_parsers.go` 文件中，在此表示感谢！

## 项目依赖

本项目使用了以下Go标准库：

- [`bytes`](https://golang.org/pkg/bytes/)：操作字节切片的函数。
- [`context`](https://golang.org/pkg/context/)：定义了Context类型，用于在API边界和进程之间传递截止日期、取消信号和其他请求范围的值。
- [`encoding/json`](https://golang.org/pkg/encoding/json/)：编码和解码JSON对象的函数。
- [`errors`](https://golang.org/pkg/errors/)：创建错误和操作错误的函数。
- [`fmt`](https://golang.org/pkg/fmt/)：格式化I/O函数。
- [`io`](https://golang.org/pkg/io/)：I/O原语函数。
- [`log/slog`](https://golang.org/pkg/log/slog/)：结构化日志服务。
- [`net`](https://golang.org/pkg/net/)：网络I/O原语的函数。
- [`net/http`](https://golang.org/pkg/net/http/)：HTTP客户端和服务器实现。
- [`os`](https://golang.org/pkg/os/)：操作系统功能的函数。
- [`os/signal`](https://golang.org/pkg/os/signal/)：接收操作系统信号的函数。
- [`regexp`](https://golang.org/pkg/regexp/)：正则表达式搜索。
- [`strconv`](https://golang.org/pkg/strconv/)：将字符串转换为基本类型的函数。
- [`strings`](https://golang.org/pkg/strings/)：操作字符串的函数。
- [`sync`](https://golang.org/pkg/sync/)：基本的同步原语。
- [`syscall`](https://golang.org/pkg/syscall/)：访问操作系统底层调用的函数。
- [`time`](https://golang.org/pkg/time/)：测量和显示时间的函数。

本项目还使用了以下第三方库：

- [`github.com/redis/go-redis/v9`](https://github.com/go-redis/redis)：Go语言Redis客户端。
- [`github.com/prometheus/client_golang`](https://github.com/prometheus/client_golang)：Prometheus 指标采集与暴露。
- [`github.com/modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk)：MCP（Model Context Protocol）Go SDK。
- [`golang.org/x/net/idna`](https://pkg.go.dev/golang.org/x/net/idna)：实现了IDNA（国际化域名在应用程序）规范。
- [`golang.org/x/net/publicsuffix`](https://pkg.go.dev/golang.org/x/net/publicsuffix)：实现了公共后缀列表规范。
- [`gopkg.in/yaml.v3`](https://gopkg.in/yaml.v3)：YAML 解析库。

WHOIS/RDAP 服务器列表来自于：
- [IANA](https://www.iana.org/domains/root/db)
- [IANA RDAP Bootstrap](https://data.iana.org/rdap/)
- [IANA RDAP Bootstrap (IPv4)](https://data.iana.org/rdap/ipv4.json)
- [IANA RDAP Bootstrap (IPv6)](https://data.iana.org/rdap/ipv6.json)
- [IANA RDAP Bootstrap (AS)](https://data.iana.org/rdap/asn.json)
