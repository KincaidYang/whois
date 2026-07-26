# Metrics

`GET /metrics` serves the Prometheus exposition format, alongside the Go
runtime and process collectors the client library registers by default. The
endpoint is not exempt from API key authentication: on an instance with
`auth.keys` configured, the scraper needs a key like any other client.

## Request metrics

### `whois_http_requests_total{type, status_code}`

Counter. One increment per completed query, labelled with what was queried and
the status the response carried.

`type` is the resource kind the request resolved to:

| `type` | Source |
|---|---|
| `domain`, `ip`, `asn` | A query over HTTP, on either the root path or a typed path (`/domain/…`, `/ip/…`, `/autnum/…`) |
| `unknown` | The input was not a valid domain, IP or ASN — or the request was rejected by the concurrency limiter before it could be classified |
| `batch` | `POST /batch` |
| `mcp` | The `whois_lookup` MCP tool |
| `mcp_batch` | The `whois_batch_lookup` MCP tool |

`status_code` is the HTTP status of the response. For the MCP tool types it is
the status the underlying query produced (`200`, `404`, `400` …), which is what
the tool reports as its error state — the MCP transport itself answers `200`
either way. For `mcp_batch` it describes the batch call, not the individual
queries, whose statuses are inside the returned payload.

Requests turned away by the concurrency limiter are counted with
`status_code="429"` and no latency observation.

### `whois_http_request_duration_seconds{type}`

Histogram (default buckets) of end-to-end handler latency, with the same `type`
label. Cache hits and upstream queries are both in here, so the distribution is
bimodal: use it for user-visible latency, and `whois_upstream_duration_seconds`
for how the registries themselves are behaving.

### `whois_client_requests_total{client, status_code}`

Counter, **only populated when `auth.keys` is configured**. `client` is the
key's display name, or `unauthenticated` for requests that presented no valid
key (counted with `status_code="401"`). This is the per-key view of traffic:
which key is using the instance, and how much of its traffic is being rejected
by its own `rateLimit`.

## Cache metrics

### `whois_cache_requests_total{backend, result}`

Counter. `backend` is `memory` or `redis`; `result` is `hit`, `miss` or
`error`. A Redis `error` is a genuine backend failure — a caller's cancelled
request is not counted as one. With the fallback cache, one lookup can produce
a `redis` result and a `memory` result.

### `whois_cache_evictions_total{backend}`

Counter of entries evicted from the in-memory LRU because it reached
`cache.memoryMaxSize`. Expiry is not an eviction. A rising rate means the
working set no longer fits and the hit ratio is being paid for it.

## Upstream metrics

### `whois_upstream_duration_seconds{protocol, tld}`

Histogram of how long the registry took, labelled `protocol` (`rdap` or
`whois`) and `tld`. IP queries use the pseudo-TLD `_ip` and ASN queries `_asn`.

Only queries that actually left this instance are observed here, so comparing
its count with `whois_http_requests_total` gives the effective cache hit ratio
— as long as batch queries are off. A batch request counts once in
`whois_http_requests_total` but can produce one upstream query per item, so
with batch traffic the two are no longer per-request comparable.

> The `tld` label has one series per TLD queried — on a busy open instance that
> is a few hundred series per protocol. That is deliberate (a single misbehaving
> registry is the thing you want to find), but if cardinality matters in your
> setup, drop or aggregate the label in the scrape config.

## Bootstrap metrics

### `whois_bootstrap_refresh_total{result}`

Counter of IANA RDAP bootstrap refresh rounds, one per `bootstrap.interval`.
`result` is:

- `success` — all four bootstrap files fetched
- `partial` — some categories failed; those keep their last-known-good data
- `failure` — nothing was fetched; the active index is untouched

### `whois_bootstrap_last_fetch_timestamp_seconds`

Gauge holding the Unix timestamp of the last fully successful refresh, or `0`
if none has succeeded since startup. Staleness in seconds:

```promql
time() - whois_bootstrap_last_fetch_timestamp_seconds
```

Staleness is unbounded by design: a category that keeps failing keeps serving
its last good data rather than falling back to the compiled-in baseline, so
this gauge is the only thing that will tell you the data has stopped moving.

## Suggested alerts

```yaml
# The RDAP server list has stopped updating. Below one day this is normal
# (the default bootstrap.interval is 86400s); a whole day past that is not.
# The gauge is 0 both on an instance with bootstrap.interval: 0 and on one
# that has never had a successful refresh, so it is guarded here and the
# second alert covers the never-succeeded case.
- alert: WhoisBootstrapStale
  expr: |
    whois_bootstrap_last_fetch_timestamp_seconds > 0
      and time() - whois_bootstrap_last_fetch_timestamp_seconds > 172800
  for: 1h

# Refreshes are being attempted and none is succeeding. Silent on an instance
# with refresh disabled, which attempts nothing.
- alert: WhoisBootstrapNeverSucceeds
  expr: |
    sum(rate(whois_bootstrap_refresh_total[6h])) > 0
      and sum(rate(whois_bootstrap_refresh_total{result="success"}[6h])) == 0
  for: 1h

# The cache backend is failing, so every request is going upstream.
- alert: WhoisCacheErrors
  expr: |
    sum(rate(whois_cache_requests_total{result="error"}[5m]))
      / sum(rate(whois_cache_requests_total[5m])) > 0.05
  for: 10m

# Server-side failures. Queries for resources that do not exist answer 404,
# so a sustained 5xx rate is this instance or its upstreams, not the input.
- alert: WhoisServerErrors
  expr: |
    sum(rate(whois_http_requests_total{status_code=~"5.."}[5m]))
      / sum(rate(whois_http_requests_total[5m])) > 0.02
  for: 10m

# Requests are being turned away by server.rateLimit — either the limit is too
# low for the traffic, or upstream queries are taking long enough to fill it.
- alert: WhoisConcurrencyRejections
  expr: sum(rate(whois_http_requests_total{status_code="429"}[5m])) > 1
  for: 15m

# One registry has become slow. Excludes the pseudo-TLDs so an RIR's latency
# does not hide behind the domain traffic.
- alert: WhoisUpstreamSlow
  expr: |
    histogram_quantile(0.95,
      sum by (le, protocol, tld) (
        rate(whois_upstream_duration_seconds_bucket{tld!~"_ip|_asn"}[10m])
      )
    ) > 5
  for: 15m
```

## Useful queries

```promql
# Cache hit ratio (requests that never reached a registry). Only meaningful
# while batch queries are off, which is the default: a batch counts as one
# request but can issue one upstream query per item, so with batch traffic the
# numerator and the denominator count different things and the ratio can even
# come out negative.
1 - (
  sum(rate(whois_upstream_duration_seconds_count[5m]))
    / sum(rate(whois_http_requests_total[5m]))
)

# Traffic split by entry point — how much of this instance is MCP.
sum by (type) (rate(whois_http_requests_total[5m]))

# p95 user-visible latency per resource type.
histogram_quantile(0.95,
  sum by (le, type) (rate(whois_http_request_duration_seconds_bucket[5m]))
)

# Which API key is consuming the instance.
sum by (client) (rate(whois_client_requests_total[5m]))
```
