package handle_resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/KincaidYang/whois/config"
	"github.com/KincaidYang/whois/rdap_tools"
	"github.com/KincaidYang/whois/server_lists"
	"github.com/KincaidYang/whois/utils"
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

	// Check if the RDAP information for the IP is cached
	key := fmt.Sprintf("%s%s", cacheKeyPrefix, resource)
	cacheResult, err := utils.GetFromCache(ctx, config.CacheManager, key)
	if err != nil {
		// If there's an error during caching, return an HTTP error
		utils.HandleInternalError(w, err)
		return
	}

	if cacheResult.Found {
		// If the RDAP information is cached, return the cached result
		utils.HandleCacheResponse(w, cacheResult.Data, "application/json")
		return
	}

	// Query the RDAP information for the IP
	queryresult, err := rdap_tools.RDAPQueryIP(resource, tld)
	if err != nil {
		utils.HandleQueryError(w, err)
		return
	}

	// Parse the RDAP response
	ipInfo, err := rdap_tools.ParseRDAPResponseforIP(queryresult)
	if err != nil {
		utils.HandleInternalError(w, err)
		return
	}

	// Marshal the result to JSON
	resultBytes, err := json.Marshal(ipInfo)
	if err != nil {
		utils.HandleInternalError(w, err)
		return
	}
	queryResult := string(resultBytes)

	// Cache the RDAP information
	err = utils.SetToCache(ctx, config.CacheManager, key, queryResult, config.CacheExpiration)
	if err != nil {
		// Log the error but don't fail the request
		// The response will still be returned to the user
	}

	// Return the RDAP information
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, queryResult)
}
