package handle_resources

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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
		if utils.IsNegativeCacheHit(w, cacheResult.Data) {
			return
		}
		utils.HandleCacheResponse(w, cacheResult.Data, "application/json")
		return
	}

	// Parse the IP and find the RDAP server URL
	ip := net.ParseIP(resource)
	serverURL, _ := server_lists.LookupIPKey(ip)

	// Query and parse the RDAP information, deduplicating concurrent misses
	outcome, err := dedupedQuery(ctx, key, func(qctx context.Context) (queryOutcome, error) {
		queryResult, err := rdap_tools.RDAPQueryIP(qctx, resource, serverURL)
		if err != nil {
			return queryOutcome{}, err
		}

		ipInfo, err := rdap_tools.ParseRDAPResponseforIP(queryResult)
		if err != nil {
			return queryOutcome{}, err
		}

		resultBytes, err := json.Marshal(ipInfo)
		if err != nil {
			return queryOutcome{}, err
		}

		result := string(resultBytes)
		if err := utils.SetToCache(qctx, config.CacheManager, key, result, config.CacheExpiration); err != nil {
			slog.Warn("cache write error", "key", key, "err", err)
		}
		return queryOutcome{body: result, contentType: "application/json"}, nil
	})
	if err != nil {
		utils.HandleQueryError(w, err)
		return
	}

	// Return the RDAP information
	w.Header().Set("Content-Type", outcome.contentType)
	fmt.Fprint(w, outcome.body)
}
