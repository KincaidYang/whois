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
	"github.com/KincaidYang/whois/utils"
)

// HandleIP function is used to handle the HTTP request for querying the RDAP information for a given IP.
func HandleIP(ctx context.Context, w http.ResponseWriter, resource string, cacheKeyPrefix string) {
	// Check cache first before doing any lookups
	key := fmt.Sprintf("%s%s", cacheKeyPrefix, resource)
	cacheResult, err := utils.GetFromCache(ctx, config.CacheManager, key)
	if err != nil {
		utils.HandleInternalError(w, err)
		return
	}
	if cacheResult.Found {
		utils.HandleCacheResponse(w, cacheResult.Data, "application/json")
		return
	}

	// Parse the IP and find the corresponding RDAP server key
	ip := net.ParseIP(resource)
	tld, _ := server_lists.LookupIPKey(ip)

	// Query the RDAP information for the IP
	queryresult, err := rdap_tools.RDAPQueryIP(ctx, resource, tld)
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

	// Cache the RDAP information
	err = utils.SetToCache(ctx, config.CacheManager, key, string(resultBytes), config.CacheExpiration)
	if err != nil {
		log.Printf("cache write error for key %s: %v", key, err)
	}

	// Return the RDAP information
	w.Header().Set("Content-Type", "application/json")
	w.Write(resultBytes)
}
