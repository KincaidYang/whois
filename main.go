package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/KincaidYang/whois/config"
	"github.com/KincaidYang/whois/handle_resources"
)

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
	if len(config.ConcurrencyLimiter) == config.RateLimit {
		log.Printf("Rate limit reached, waiting for a slot to become available...\n")
	}
	config.ConcurrencyLimiter <- struct{}{}
	config.Wg.Add(1)
	defer func() {
		config.Wg.Done()
		<-config.ConcurrencyLimiter
	}()

	ctx := context.Background()
	resource := strings.TrimPrefix(r.URL.Path, "/")
	resource = strings.ToLower(resource)

	cacheKeyPrefix := "whois:"

	// Validate user input
	if net.ParseIP(resource) != nil {
		handle_resources.HandleIP(ctx, w, resource, cacheKeyPrefix)
	} else if isASN(resource) {
		handle_resources.HandleASN(ctx, w, resource, cacheKeyPrefix)
	} else if isDomain(resource) {
		handle_resources.HandleDomain(ctx, w, resource, cacheKeyPrefix)
	} else {
		// If input is invalid, return HTTP 400 Bad Request
		http.Error(w, "Invalid input. Please provide a valid domain, IP, or ASN.", http.StatusBadRequest)
		return
	}
}

func main() {
	// Note: Redis connection is now checked during config initialization
	// The service will continue with memory cache if Redis is unavailable

	// Health check endpoints (new, non-breaking)
	http.HandleFunc("/health", handle_resources.HandleHealth)
	http.HandleFunc("/ready", handle_resources.HandleReady)
	http.HandleFunc("/info", handle_resources.HandleInfo)

	// Main query handler
	http.HandleFunc("/", handler)
	go func() {
		fmt.Printf("Server is listening on port %d...\n", config.Port)
		err := http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil)
		if err != nil {
			fmt.Println("Server failed to start:", err)
			os.Exit(1)
		}
	}()

	// Add a signal listener. When a shutdown signal is received, wait for all queries to complete before shutting down the server.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Received shutdown signal, waiting for all queries to complete...")
	config.Wg.Wait()

	log.Println("All queries completed. Shutting down server...")
	if config.RedisClient != nil {
		config.RedisClient.Close()
	}
	os.Exit(0)
}
