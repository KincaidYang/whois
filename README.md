[![CodeQL](https://github.com/KincaidYang/whois/actions/workflows/codeql.yml/badge.svg)](https://github.com/KincaidYang/whois/actions/workflows/codeql.yml) [![Go](https://github.com/KincaidYang/whois/actions/workflows/go.yml/badge.svg)](https://github.com/KincaidYang/whois/actions/workflows/go.yml) 

## 介绍
基于 Golang 实现的域名 Whois 查询工具，支持所有允许公开查询的 TLD 后缀的域名信息查询。据 ICANN 《通用顶级域名注册数据临时政策细则（Temporary Specification for gTLD Registration Data）》和欧盟《通用数据保护条例》合规要求，程序只返回了部分必要的信息（详见下方返回结果示例），不会返回所有者的`联系方式`、`地址`、`电话`、`邮箱`等字段。

## 使用方法
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
vim config.json
```
```json
{
    "redis": {
        "addr": "localhost:6379",
        "password": "",
        "db": 0
    },
    "cacheExpiration": 3600,
    "port": 8043,
    "rateLimit": 50
}
```
根据需要修改 Redis 地址、端口、密码、数据库、缓存时间、监听端口、限频等参数。
> ⚠️ **Warning:** 限频针对的是程序向 whois 服务器发起的请求，而非用户向本程序发起的请求。例如，您将限频设置为 50，那么程序向 whois 服务器发起的请求将不会超过 50 次/秒，但是用户向本程序发起的请求不受限制。请您通过 Nginx 等工具对本程序进行限流，以防止恶意请求。

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
[Unit]
Description=whois
After=network.target

[Service]
Type=simple
User=www
Group=www
ExecStart=/path/to/whois/whois
WorkingDirectory=/path/to/whois
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
### 使用
GET 请求
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

## 已知问题
程序向注册局查询 Whois 信息主要依靠 RDAP 协议查询，但由于大部分 ccTLD 不支持 RDAP 协议，程序会对其原始的 Whois 信息格式化后返回 JSON 数据，但由于本人精力有限，未对所有的 ccTLD 后缀进行适配，程序可能会直接返回 `text` 数据，如您常用的后缀没用被覆盖，可以提交 Issue 或者贡献匹配规则至 `whois_parsers.go` 文件中，在此表示感谢！

您可根据`content-type`来判断返回数据格式。
