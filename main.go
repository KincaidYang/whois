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
	"github.com/KincaidYang/whois/metrics"
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

// Pre-compiled regular expressions for better performance
var (
	asnRegex    = regexp.MustCompile(`^(?i)(as|asn)?\d+$`)
	domainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

// isASN function is used to check if the given resource is an Autonomous System Number (ASN).
func isASN(resource string) bool {
	return asnRegex.MatchString(resource)
}

// isDomain function is used to check if the given resource is a valid domain name.
func isDomain(resource string) bool {
	return domainRegex.MatchString(resource)
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

	ctx := r.Context()
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

	// Health check endpoints
	http.HandleFunc("/health", handle_resources.HandleHealth)
	http.HandleFunc("/ready", handle_resources.HandleReady)
	http.HandleFunc("/info", handle_resources.HandleInfo)

	// Prometheus metrics endpoint
	http.Handle("/metrics", promhttp.Handler())

	// Main query handler
	http.HandleFunc("/", handler)

	srv := &http.Server{Addr: fmt.Sprintf(":%d", config.Port)}

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
