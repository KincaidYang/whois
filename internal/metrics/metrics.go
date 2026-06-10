package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTPRequestsTotal counts completed HTTP requests by resource type and HTTP status code.
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "whois_http_requests_total",
			Help: "Total number of HTTP requests by resource type and status code.",
		},
		[]string{"type", "status_code"},
	)

	// HTTPRequestDuration tracks the latency of HTTP requests by resource type.
	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "whois_http_request_duration_seconds",
			Help:    "HTTP request latency by resource type.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"type"},
	)

	// CacheRequestsTotal counts cache lookups by backend (memory/redis) and result (hit/miss).
	CacheRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "whois_cache_requests_total",
			Help: "Total cache lookups by backend and result.",
		},
		[]string{"backend", "result"},
	)

	// CacheEvictionsTotal counts cache evictions by backend.
	CacheEvictionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "whois_cache_evictions_total",
			Help: "Total cache evictions by backend.",
		},
		[]string{"backend"},
	)

	// UpstreamDuration tracks how long upstream RDAP or WHOIS queries take by protocol and TLD.
	// For IP queries the tld label is "_ip"; for ASN queries it is "_asn".
	UpstreamDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "whois_upstream_duration_seconds",
			Help:    "Upstream RDAP/WHOIS query latency by protocol and TLD.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"protocol", "tld"},
	)

	// BootstrapRefreshTotal counts IANA bootstrap refresh attempts by result (success/failure).
	BootstrapRefreshTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "whois_bootstrap_refresh_total",
			Help: "IANA RDAP bootstrap refresh attempts by result.",
		},
		[]string{"result"},
	)

	// BootstrapLastFetchTimestamp is the Unix timestamp of the last successful IANA bootstrap fetch.
	// Age in seconds can be computed in PromQL as: time() - whois_bootstrap_last_fetch_timestamp_seconds
	BootstrapLastFetchTimestamp = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "whois_bootstrap_last_fetch_timestamp_seconds",
			Help: "Unix timestamp of the last successful IANA bootstrap fetch. 0 if never fetched.",
		},
	)
)
