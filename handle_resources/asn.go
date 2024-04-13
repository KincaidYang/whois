package handle_resources

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/KincaidYang/whois/config"
	"github.com/KincaidYang/whois/rdap_tools"
	"github.com/KincaidYang/whois/server_lists"
	"github.com/redis/go-redis/v9"
)

// HandleASN function is used to handle the HTTP request for querying the RDAP information for a given ASN (Autonomous System Number).
func HandleASN(ctx context.Context, w http.ResponseWriter, resource string, cacheKeyPrefix string) {
	// Parse the ASN
	asn := strings.TrimPrefix(resource, "asn")
	if asn == resource {
		asn = strings.TrimPrefix(resource, "as")
	}
	asnInt, err := strconv.Atoi(asn)
	if err != nil {
		// handle error
		return
	}

	// Generate the cache key
	key := fmt.Sprintf("%s%s", cacheKeyPrefix, asn)

	// Check if the RDAP information for the ASN is cached in Redis
	cacheResult, err := config.RedisClient.Get(ctx, key).Result()
	if err == nil {
		// If the RDAP information is cached, return the cached result
		log.Printf("Serving cached result for resource: %s\n", asn)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, cacheResult)
		return
	} else if err != redis.Nil {
		// If there's an error during caching, return an HTTP error
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Find the corresponding TLD from the TLDToRdapServer map
	var tld string
	for rangeStr := range server_lists.TLDToRdapServer {
		if !strings.Contains(rangeStr, "-") {
			continue
		}
		rangeParts := strings.Split(rangeStr, "-")
		if len(rangeParts) != 2 {
			continue
		}
		lower, err := strconv.Atoi(rangeParts[0])
		if err != nil {
			continue
		}
		upper, err := strconv.Atoi(rangeParts[1])
		if err != nil {
			continue
		}
		if asnInt >= lower && asnInt <= upper {
			tld = rangeStr
			break
		}
	}

	// Query the RDAP information for the ASN
	queryresult, err := rdap_tools.RDAPQueryASN(asn, tld)
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
	asnInfo, err := rdap_tools.ParseRDAPResponseforASN(queryresult)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Cache the RDAP information in Redis
	resultBytes, err := json.Marshal(asnInfo)
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
