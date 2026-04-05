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

	// UpstreamDuration tracks how long upstream RDAP or WHOIS queries take.
	UpstreamDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "whois_upstream_duration_seconds",
			Help:    "Upstream RDAP/WHOIS query latency by protocol.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"protocol"},
	)
)
