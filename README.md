[![Go Reference](https://pkg.go.dev/badge/github.com/KincaidYang/whois.svg)](https://pkg.go.dev/github.com/KincaidYang/whois) [![Go](https://github.com/KincaidYang/whois/actions/workflows/go.yml/badge.svg)](https://github.com/KincaidYang/whois/actions/workflows/go.yml) [![CodeQL](https://github.com/KincaidYang/whois/actions/workflows/codeql.yml/badge.svg)](https://github.com/KincaidYang/whois/actions/workflows/codeql.yml)

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
本程序需要 Redis 服务支持，您可参照 https://redis.io/docs/install/install-redis/install-redis-on-linux/ 进行安装。

### 编辑配置文件
```bash
vim config.yaml
```
```yaml
redis:
  addr: "redis:6379"
  password: ""
  db: 0
cacheExpiration: 3600
port: 8043
rateLimit: 50
ProxyServer: "http://127.0.0.1:8080"
ProxySuffixes: 
ProxyUsername: ""
ProxyPassword: ""
```
根据需要修改 Redis 地址、端口、密码、数据库、缓存时间、监听端口、限频、如果需要在向注册局查询时使用代理，请配置代理服务器、需要代理的后缀、代理服务器用户名&密码（可选）等参数。
> ⚠️ **Warning:** 限频针对的是程序向 whois 服务器发起的请求，而非用户向本程序发起的请求。例如，您将限频设置为 50，那么程序向注册局 whois 服务器发起的请求将不会超过 50 次/秒，但是用户向本程序发起的请求不受限制。请您通过 Nginx 等工具对本程序进行限流，以防止恶意请求。

### 运行
```bash
./whois
```
**注意：** 本程序默认监听 8043 端口。

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

#### 查询域名 Whois 信息
```bash
curl http://localhost:8043/example.com
```
返回结果
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

#### 查询 IPv4 Whois 信息
```bash
curl http://localhost:8043/1.12.34.56
```
返回结果
```json
{
  "IP Network": "1.12.0.0 - 1.15.255.255",
  "Address Range": "1.12.0.0 - 1.15.255.255",
  "Network Name": "TencentCloud",
  "CIDR": "1.12.0.0/14",
  "Network Type": "ALLOCATED PORTABLE",
  "Country": "CN",
  "Status": [
    "active"
  ],
  "Creation Date": "2010-05-10T22:46:58Z",
  "Updated Date": "2023-11-28T00:51:33Z",
  "Remarks": [
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
  "IP Network": "2402:4e00::/32",
  "Address Range": "2402:4e00:: - 2402:4e00:ffff:ffff:ffff:ffff:ffff:ffff",
  "Network Name": "TencentCloud",
  "CIDR": "2402:4e00::/32",
  "Network Type": "ALLOCATED PORTABLE",
  "Country": "CN",
  "Status": [
    "active"
  ],
  "Creation Date": "2010-05-12T23:13:32Z",
  "Updated Date": "2024-01-31T06:27:10Z",
  "Remarks": [
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
  "AS Number": "AS205794",
  "Network Name": "RTTW-AS",
  "Status": [
    "active"
  ],
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

## 已知问题
程序向注册局查询 Whois 信息主要依靠 RDAP 协议查询，但由于大部分 ccTLD 不支持 RDAP 协议，程序会对其原始的 Whois 信息格式化后返回 JSON 数据，但由于本人精力有限，未对所有的 ccTLD 后缀进行适配，程序可能会直接返回 `text` 数据，如您常用的后缀没用被覆盖，可以提交 Issue 或者贡献匹配规则至 `whois_parsers.go` 文件中，在此表示感谢！

您可根据`content-type`来判断返回数据格式。

## 项目依赖

本项目使用了以下Go标准库：

- [`bytes`](https://golang.org/pkg/bytes/)：操作字节切片的函数。
- [`context`](https://golang.org/pkg/context/)：定义了Context类型，用于在API边界和进程之间传递截止日期、取消信号和其他请求范围的值。
- [`encoding/json`](https://golang.org/pkg/encoding/json/)：编码和解码JSON对象的函数。
- [`errors`](https://golang.org/pkg/errors/)：创建错误和操作错误的函数。
- [`fmt`](https://golang.org/pkg/fmt/)：格式化I/O函数。
- [`io`](https://golang.org/pkg/io/)：I/O原语函数。
- [`log`](https://golang.org/pkg/log/)：简单的日志服务。
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
- [`golang.org/x/net/idna`](https://pkg.go.dev/golang.org/x/net/idna)：实现了IDNA（国际化域名在应用程序）规范。
- [`golang.org/x/net/publicsuffix`](https://pkg.go.dev/golang.org/x/net/publicsuffix)：实现了公共后缀列表规范。
- [`gopkg.in/yaml.v2`](https://gopkg.in/yaml.v2)：YAML 解析库。

WHOIS/RDAP 服务器列表来自于：
- [IANA](https://www.iana.org/domains/root/db)
- [IANA RDAP Bootstrap](https://data.iana.org/rdap/)
- [IANA RDAP Bootstrap (IPv4)](https://data.iana.org/rdap/ipv4.json)
- [IANA RDAP Bootstrap (IPv6)](https://data.iana.org/rdap/ipv6.json)
- [IANA RDAP Bootstrap (AS)](https://data.iana.org/rdap/asn.json)
