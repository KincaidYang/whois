package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/KincaidYang/whois/config"
	"github.com/KincaidYang/whois/handle_resources"
	"github.com/KincaidYang/whois/mcp_server"
	"github.com/KincaidYang/whois/metrics"
	"github.com/KincaidYang/whois/server_lists"
	"github.com/KincaidYang/whois/utils"
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

func handler(w http.ResponseWriter, r *http.Request) {
	config.Wg.Add(1)
	select {
	case config.ConcurrencyLimiter <- struct{}{}:
	default:
		config.Wg.Done()
		slog.WarnContext(r.Context(), "rate limit reached", "path", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":"too many concurrent requests"}`)
		metrics.HTTPRequestsTotal.WithLabelValues("unknown", "429").Inc()
		return
	}
	defer func() {
		config.Wg.Done()
		<-config.ConcurrencyLimiter
	}()

	ctx, cancel := context.WithTimeout(r.Context(), config.RequestTimeout)
	defer cancel()
	resource := strings.TrimPrefix(r.URL.Path, "/")
	resource = strings.ToLower(resource)

	// ?raw requests the unparsed WHOIS text (domains only; RDAP-backed IP
	// and ASN lookups have no raw-text form). ?raw=0 / ?raw=false opt out.
	rawValue := r.URL.Query().Get("raw")
	raw := r.URL.Query().Has("raw") && rawValue != "0" && rawValue != "false"

	cacheKeyPrefix := "whois:"
	sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
	start := time.Now()

	var resourceType string
	if net.ParseIP(resource) != nil {
		resourceType = "ip"
		if raw {
			utils.HandleHTTPError(sw, utils.ErrorTypeBadRequest, "Raw output is only supported for domain queries.")
		} else {
			handle_resources.HandleIP(ctx, sw, resource, cacheKeyPrefix)
		}
	} else if utils.IsASN(resource) {
		resourceType = "asn"
		if raw {
			utils.HandleHTTPError(sw, utils.ErrorTypeBadRequest, "Raw output is only supported for domain queries.")
		} else {
			handle_resources.HandleASN(ctx, sw, resource, cacheKeyPrefix)
		}
	} else if utils.IsDomain(resource) {
		resourceType = "domain"
		handle_resources.HandleDomain(ctx, sw, resource, cacheKeyPrefix, raw)
	} else {
		resourceType = "unknown"
		utils.HandleHTTPError(sw, utils.ErrorTypeBadRequest, "Invalid input. Please provide a valid domain, IP, or ASN.")
	}

	elapsed := time.Since(start).Seconds()
	metrics.HTTPRequestsTotal.WithLabelValues(resourceType, strconv.Itoa(sw.code)).Inc()
	metrics.HTTPRequestDuration.WithLabelValues(resourceType).Observe(elapsed)
}

func main() {

	// Start RDAP bootstrap refresh (initial fetch + periodic updates).
	// Disabled when BootstrapInterval is 0 or unset.
	if config.BootstrapInterval > 0 {
		bootstrapCtx, bootstrapCancel := context.WithCancel(context.Background())
		defer bootstrapCancel()
		server_lists.StartBootstrapRefresh(bootstrapCtx, config.HttpClient, config.BootstrapInterval)
	}

	// Health check endpoints
	http.HandleFunc("/health", handle_resources.HandleHealth)
	http.HandleFunc("/ready", handle_resources.HandleReady)
	http.HandleFunc("/info", handle_resources.HandleInfo)

	// Prometheus metrics endpoint
	http.Handle("/metrics", promhttp.Handler())

	// MCP Streamable HTTP endpoint
	http.Handle("/mcp", mcp_server.NewHandler(config.Version))

	// Main query handler
	http.HandleFunc("/", handler)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.Port),
		Handler: withRequestID(http.DefaultServeMux),
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
		c.Close()
	}
	if config.RedisClient != nil {
		config.RedisClient.Close()
	}
}
