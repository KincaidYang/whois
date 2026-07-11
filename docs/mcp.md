# MCP Integration

The service exposes a [Model Context Protocol](https://modelcontextprotocol.io)
endpoint at `/mcp` (Streamable HTTP transport, stateless, plain JSON
responses), so AI assistants can run WHOIS/RDAP lookups as a tool — no
separate MCP server process is needed; every deployment of this service is
already one.

```text
https://your-instance/mcp
```

You can try it against the public demo instance: `https://whois.ddnsip.cn/mcp`.

## Tools

### `whois_lookup`

```json
{ "query": "example.com" }
```

`query` accepts a domain name (IDN/Unicode names work), an IPv4/v6 address or
CIDR prefix, or an ASN (`AS13335`). The result is the same RDAP-style JSON the
REST API returns.

### `whois_batch_lookup`

```json
{ "queries": ["example.com", "8.8.8.8", "AS15169"] }
```

The MCP face of `POST /batch`: disabled unless the operator sets
`batch.enabled: true`, capped at `batch.maxItems` queries per call, and
charged against per-key rate limits at one request per query.

## Client setup

### Claude Code

```bash
claude mcp add --transport http whois https://whois.ddnsip.cn/mcp
```

### Claude Desktop / claude.ai

Settings → Connectors → **Add custom connector**, then enter the `/mcp` URL.

### Cursor

`.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global):

```json
{
  "mcpServers": {
    "whois": {
      "url": "https://whois.ddnsip.cn/mcp"
    }
  }
}
```

### Other clients

Any client that speaks MCP over Streamable HTTP works the same way: point it
at the `/mcp` URL. There is no SSE requirement — tool calls are answered with
plain `application/json`.

## Authentication

When the instance has API key authentication enabled (`auth.keys` in the
config), `/mcp` requires a key like every other endpoint. Send it as an HTTP
header — either `Authorization: Bearer <key>` or `X-API-Key: <key>`:

```bash
claude mcp add --transport http whois https://your-instance/mcp \
  --header "X-API-Key: your-secret-key"
```

```json
{
  "mcpServers": {
    "whois": {
      "url": "https://your-instance/mcp",
      "headers": { "X-API-Key": "your-secret-key" }
    }
  }
}
```

## Example

> **User:** When does example.com expire, and is DNSSEC enabled?
>
> **Assistant:** *calls `whois_lookup` with `{"query": "example.com"}`* —
> example.com expires on 2026-08-13, and DNSSEC is enabled
> (`secureDNS.delegationSigned: true`).

## Notes for operators

- `mcp.localhostProtection` enables DNS-rebinding protection: `/mcp` then only
  accepts requests whose `Host` header is localhost. Keep it `false` behind a
  reverse proxy (the public hostname would be rejected); set it `true` when
  the server is reached directly on localhost.
- MCP calls share the same concurrency limiter, request timeout, cache and
  rate-limit accounting as plain HTTP queries.
