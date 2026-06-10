# Error Types

Error responses follow [RFC 9457 (Problem Details for HTTP APIs)](https://www.rfc-editor.org/rfc/rfc9457)
and are served with `Content-Type: application/problem+json`:

```json
{
  "type": "https://github.com/KincaidYang/whois/blob/main/docs/errors.md#not-found",
  "title": "Resource not found",
  "status": 404
}
```

`type` and `title` are stable identifiers you can switch on; `detail`, when
present, is human-readable context that may change between releases.

## not-found

**Status: 404.** The domain, IP network, or ASN is not registered, or the
registry returned no data for it. Not-found results are negatively cached for
a short time (`cache.negativeExpiration`, default 60s).

## query-denied

**Status: 403.** The upstream registry refused to answer the query (some
registries deny queries from data centers or rate-limit by source). Denied
results are negatively cached like not-found.

## bad-request

**Status: 400.** The input is not a valid domain, IP address, or ASN — or a
query parameter combination is unsupported (e.g. `?raw=1` on an IP/ASN query,
which has no raw WHOIS form).

## rate-limited

**Status: 429.** The server's concurrent-request limit (`server.rateLimit` in
config) was reached. Retry after a short delay.

## query-failed

**Status: 500.** The upstream WHOIS/RDAP query failed (network error, upstream
timeout, malformed upstream response). Transient — retrying later usually
succeeds. Details are logged server-side with the request's `X-Request-ID`.

## internal-error

**Status: 500.** An unexpected server-side error (cache backend failure and
similar). Details are logged server-side with the request's `X-Request-ID`.
