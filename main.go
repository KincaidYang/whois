package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
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
	"golang.org/x/net/idna"
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

// Pre-compiled regular expressions for better performance
var (
	asnRegex = regexp.MustCompile(`^(?i)(as|asn)?\d+$`)
	// domainRegex is matched against the ASCII/punycode form (see isDomain), so
	// the final label may be either an alphabetic TLD or a punycode TLD such as
	// "xn--fiqs8s" (.中国), which contains digits and hyphens.
	domainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9-]+)$`)
)

// requestTimeout bounds how long a single query may take, so a slow upstream
// WHOIS/RDAP server cannot hold a concurrency slot indefinitely. It must stay
// below the server's WriteTimeout (20s) so the handler returns first, and above
// the per-upstream dial/read timeout (10s) to allow one full upstream attempt.
const requestTimeout = 15 * time.Second

// isASN function is used to check if the given resource is an Autonomous System Number (ASN).
func isASN(resource string) bool {
	return asnRegex.MatchString(resource)
}

// isDomain function is used to check if the given resource is a valid domain name.
// IDN (Unicode) domains such as "müller.de" or "例子.cn" are converted to their
// ASCII/punycode form before validation, matching the conversion HandleDomain
// performs, so they are accepted at the entry point.
func isDomain(resource string) bool {
	ascii, err := idna.ToASCII(resource)
	if err != nil {
		return false
	}
	return domainRegex.MatchString(ascii)
}

func handler(w http.ResponseWriter, r *http.Request) {
	config.Wg.Add(1)
	select {
	case config.ConcurrencyLimiter <- struct{}{}:
	default:
		config.Wg.Done()
		slog.Warn("rate limit reached", "path", r.URL.Path)
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

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	resource := strings.TrimPrefix(r.URL.Path, "/")
	resource = strings.ToLower(resource)

	cacheKeyPrefix := "whois:"
	sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
	start := time.Now()

	var resourceType string
	if net.ParseIP(resource) != nil {
		resourceType = "ip"
		handle_resources.HandleIP(ctx, sw, resource, cacheKeyPrefix)
	} else if isASN(resource) {
		resourceType = "asn"
		handle_resources.HandleASN(ctx, sw, resource, cacheKeyPrefix)
	} else if isDomain(resource) {
		resourceType = "domain"
		handle_resources.HandleDomain(ctx, sw, resource, cacheKeyPrefix)
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
		Addr: fmt.Sprintf(":%d", config.Port),
		// WriteTimeout must exceed the upstream query timeout (WHOIS/RDAP
		// each allow up to 10s), since the handler queries upstream
		// synchronously before writing the response.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       120 * time.Second,
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

	if config.RedisClient != nil {
		config.RedisClient.Close()
	}
}
