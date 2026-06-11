package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/handlers"
	"github.com/KincaidYang/whois/internal/mcp"
	"github.com/KincaidYang/whois/internal/metrics"
	"github.com/KincaidYang/whois/internal/serverlist"
	"github.com/KincaidYang/whois/internal/utils"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// statusWriter wraps http.ResponseWriter to capture the written status code.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.code = code
	sw.ResponseWriter.WriteHeader(code)
}

// withRequestID attaches a request ID to every request: an inbound
// X-Request-ID header is reused when it passes validation, otherwise a fresh
// ID is generated. The ID is echoed on the response and stored in the request
// context so *Context slog calls carry it (see utils.ContextHandler).
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !utils.IsValidRequestID(id) {
			id = utils.NewRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(utils.WithRequestID(r.Context(), id)))
	})
}

// bearerPrefix is the Authorization header scheme prefix; the scheme name is
// compared case-insensitively (RFC 9110 section 11.1).
const bearerPrefix = "Bearer "

// requestAuthorized reports whether the request presents a configured API
// key as "Authorization: Bearer <key>" or "X-API-Key: <key>". Both headers
// are checked, so a stale bearer token does not mask a valid X-API-Key.
func requestAuthorized(r *http.Request) bool {
	if auth := r.Header.Get("Authorization"); len(auth) > len(bearerPrefix) &&
		strings.EqualFold(auth[:len(bearerPrefix)], bearerPrefix) &&
		keyAllowed(auth[len(bearerPrefix):]) {
		return true
	}
	return keyAllowed(r.Header.Get("X-API-Key"))
}

// keyAllowed reports whether key matches one of the configured API keys,
// comparing in constant time so the comparison itself leaks nothing about the
// configured keys. The empty key never matches: it is what a request with no
// credentials presents.
func keyAllowed(key string) bool {
	if key == "" {
		return false
	}
	allowed := false
	for _, k := range config.AuthKeys {
		if subtle.ConstantTimeCompare([]byte(key), []byte(k)) == 1 {
			allowed = true
		}
	}
	return allowed
}

// withAuth enforces API key authentication when auth.keys is configured
// (empty keys leave the service open). Only /health and /ready are exempt so
// liveness probes keep working; everything else — queries, /mcp, /metrics,
// /info, /openapi.json — requires a key: an instance that enables auth is not
// meant to be publicly enumerable at all.
func withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(config.AuthKeys) == 0 || r.URL.Path == "/health" || r.URL.Path == "/ready" {
			next.ServeHTTP(w, r)
			return
		}
		if !requestAuthorized(r) {
			utils.WriteUnauthorized(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withCORS allows cross-origin browser access: every response carries
// Access-Control-Allow-Origin and preflight OPTIONS requests are answered
// directly.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID, X-Cache")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Request-ID, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// registerRoutes attaches all endpoints to mux.
func registerRoutes(mux *http.ServeMux) {
	// Health check endpoints
	mux.HandleFunc("/health", handlers.HandleHealth)
	mux.HandleFunc("/ready", handlers.HandleReady)
	mux.HandleFunc("/info", handlers.HandleInfo)

	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	// OpenAPI 3.1 service description
	mux.HandleFunc("/openapi.json", handlers.HandleOpenAPI)

	// MCP Streamable HTTP endpoint
	mux.Handle("/mcp", mcp.NewHandler(config.Version))

	// RFC 9082-style typed query paths. The ip path uses a rest wildcard so
	// CIDR prefixes ("/ip/192.0.2.0/24") keep their slash.
	mux.HandleFunc("/domain/{resource}", typedHandler("domain"))
	mux.HandleFunc("/ip/{resource...}", typedHandler("ip"))
	mux.HandleFunc("/autnum/{resource}", typedHandler("asn"))

	// Main query handler (auto-detects the resource type)
	mux.HandleFunc("/", handler)
}

// handler serves the root path, auto-detecting whether the resource is a
// domain, IP address, or ASN.
func handler(w http.ResponseWriter, r *http.Request) {
	serve(w, r, strings.TrimPrefix(r.URL.Path, "/"), "")
}

// typedHandler serves the RFC 9082-style typed paths (/domain/{resource},
// /ip/{resource}, /autnum/{resource}); want names the resource type the path
// requires.
func typedHandler(want string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, r.PathValue("resource"), want)
	}
}

// typedPathError maps a required resource type to the 400 message returned
// when the supplied resource is not of that type.
var typedPathError = map[string]string{
	"domain": "The /domain/ path requires a valid domain name.",
	"ip":     "The /ip/ path requires a valid IPv4 or IPv6 address.",
	"asn":    "The /autnum/ path requires a valid AS number.",
}

func serve(w http.ResponseWriter, r *http.Request, resource, want string) {
	config.Wg.Add(1)
	select {
	case config.ConcurrencyLimiter <- struct{}{}:
	default:
		config.Wg.Done()
		slog.WarnContext(r.Context(), "rate limit reached", "path", r.URL.Path)
		utils.WriteRateLimited(w)
		metrics.HTTPRequestsTotal.WithLabelValues("unknown", "429").Inc()
		return
	}
	defer func() {
		config.Wg.Done()
		<-config.ConcurrencyLimiter
	}()

	ctx, cancel := context.WithTimeout(r.Context(), config.RequestTimeout)
	defer cancel()
	resource = strings.ToLower(resource)

	// ?raw requests the unparsed WHOIS text (domains only; RDAP-backed IP
	// and ASN lookups have no raw-text form). ?raw=0 / ?raw=false opt out.
	rawValue := r.URL.Query().Get("raw")
	raw := r.URL.Query().Has("raw") && rawValue != "0" && rawValue != "false"

	cacheKeyPrefix := handlers.CacheKeyPrefix
	sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
	start := time.Now()

	var resourceType string
	if utils.IsIP(resource) || utils.IsCIDR(resource) {
		resourceType = "ip"
	} else if utils.IsASN(resource) {
		resourceType = "asn"
	} else if utils.IsDomain(resource) {
		resourceType = "domain"
	} else {
		resourceType = "unknown"
	}

	switch {
	case want != "" && resourceType != want:
		utils.HandleHTTPError(sw, utils.ErrorTypeBadRequest, typedPathError[want])
	case resourceType == "ip":
		if raw {
			utils.HandleHTTPError(sw, utils.ErrorTypeBadRequest, "Raw output is only supported for domain queries.")
		} else {
			handlers.HandleIP(ctx, sw, resource, cacheKeyPrefix)
		}
	case resourceType == "asn":
		if raw {
			utils.HandleHTTPError(sw, utils.ErrorTypeBadRequest, "Raw output is only supported for domain queries.")
		} else {
			handlers.HandleASN(ctx, sw, resource, cacheKeyPrefix)
		}
	case resourceType == "domain":
		handlers.HandleDomain(ctx, sw, resource, cacheKeyPrefix, raw)
	default:
		utils.HandleHTTPError(sw, utils.ErrorTypeBadRequest, "Invalid input. Please provide a valid domain, IP, or ASN.")
	}

	elapsed := time.Since(start).Seconds()
	metrics.HTTPRequestsTotal.WithLabelValues(resourceType, strconv.Itoa(sw.code)).Inc()
	metrics.HTTPRequestDuration.WithLabelValues(resourceType).Observe(elapsed)
}

func main() {
	// Load configuration and initialize logger, Redis client and cache.
	config.Load()

	// Start RDAP bootstrap refresh (initial fetch + periodic updates).
	// Disabled when BootstrapInterval is 0 or unset.
	if config.BootstrapInterval > 0 {
		bootstrapCtx, bootstrapCancel := context.WithCancel(context.Background())
		defer bootstrapCancel()
		serverlist.StartBootstrapRefresh(bootstrapCtx, config.HttpClient, config.BootstrapInterval)
	}

	registerRoutes(http.DefaultServeMux)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.Port),
		Handler: withRequestID(withCORS(withAuth(http.DefaultServeMux))),
		// WriteTimeout must exceed the upstream query timeout (WHOIS/RDAP
		// each allow up to 10s), since the handler queries upstream
		// synchronously before writing the response.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       120 * time.Second,
		// Queries arrive as URL paths with no cookies or auth headers, so
		// anything beyond a few KB of headers is abuse, not a real client.
		MaxHeaderBytes: 16 << 10, // 16 KiB
	}

	go func() {
		slog.Info("server listening", "port", config.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server failed to start", "err", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal, then drain in-flight requests before exiting.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	slog.Info("shutdown signal received, waiting for in-flight requests")
	config.Wg.Wait()

	slog.Info("all requests completed, shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "err", err)
	}

	if c, ok := config.CacheManager.(io.Closer); ok {
		if err := c.Close(); err != nil {
			slog.Warn("cache close error", "err", err)
		}
	}
	if config.RedisClient != nil {
		if err := config.RedisClient.Close(); err != nil {
			slog.Warn("redis client close error", "err", err)
		}
	}
}
