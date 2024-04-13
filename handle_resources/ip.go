package handle_resources

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/KincaidYang/whois/config"
	"github.com/KincaidYang/whois/rdap_tools"
	"github.com/KincaidYang/whois/server_lists"
	"github.com/redis/go-redis/v9"
)

// HandleIP function is used to handle the HTTP request for querying the RDAP information for a given IP.
func HandleIP(ctx context.Context, w http.ResponseWriter, resource string, cacheKeyPrefix string) {
	// Parse the IP
	ip := net.ParseIP(resource)

	// Find the corresponding TLD from the TLDToRdapServer map
	var tld string
	for cidr := range server_lists.TLDToRdapServer {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// If the key cannot be parsed as a CIDR, skip this key
			continue
		}

		if ipNet.Contains(ip) {
			tld = cidr
			break
		}
	}

	// Check if the RDAP information for the IP is cached in Redis
	key := fmt.Sprintf("%s%s", cacheKeyPrefix, resource)
	cacheResult, err := config.RedisClient.Get(ctx, key).Result()
	if err == nil {
		// If the RDAP information is cached, return the cached result
		log.Printf("Serving cached result for resource: %s\n", resource)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, cacheResult)
		return
	} else if err != redis.Nil {
		// If there's an error during caching, return an HTTP error
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Query the RDAP information for the IP
	queryresult, err := rdap_tools.RDAPQueryIP(resource, tld)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if err.Error() == "resource not found" {
			w.WriteHeader(http.StatusNotFound) // Set the status code to 404
			fmt.Fprint(w, `{"error": "Resource not found"}`)
		} else if err.Error() == "the registry denied the query" {
			w.WriteHeader(http.StatusForbidden) // Set the status code to 403
			fmt.Fprint(w, `{"error": "The registry denied the query"}`)
		} else {
			w.WriteHeader(http.StatusInternalServerError) // Set the status code to 500
			fmt.Fprint(w, `{"error": "`+err.Error()+`"}`)
		}
		return
	}

	// Parse the RDAP response
	ipInfo, err := rdap_tools.ParseRDAPResponseforIP(queryresult)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Cache the RDAP information in Redis
	resultBytes, err := json.Marshal(ipInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	queryResult := string(resultBytes)
	err = config.RedisClient.Set(ctx, key, queryResult, config.CacheExpiration).Err()
	if err != nil {
		log.Printf("Failed to cache result for resource: %s\n", resource)
	}

	// Return the RDAP information
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, queryResult)
}
