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

// isASN function is used to check if the given resource is an Autonomous System Number (ASN).
func isASN(resource string) bool {
	return regexp.MustCompile(`^(as|asn)\d+$`).MatchString(resource) || regexp.MustCompile(`^\d+$`).MatchString(resource)
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

	if net.ParseIP(resource) != nil {
		handle_resources.HandleIP(ctx, w, resource, cacheKeyPrefix)
	} else if isASN(resource) {
		handle_resources.HandleASN(ctx, w, resource, cacheKeyPrefix)
	} else {
		handle_resources.HandleDomain(ctx, w, resource, cacheKeyPrefix)
	}

}

func checkRedisConnection() {
	ctx := context.Background()
	_, err := config.RedisClient.Ping(ctx).Result()
	if err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}
}

func main() {
	// Check Redis Connection
	checkRedisConnection()

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
	config.RedisClient.Close()
	os.Exit(0)
}
