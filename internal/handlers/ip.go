package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/rdap"
	"github.com/KincaidYang/whois/internal/serverlist"
	"github.com/KincaidYang/whois/internal/utils"
)

// HandleIP function is used to handle the HTTP request for querying the RDAP information for a given IP.
func HandleIP(ctx context.Context, w http.ResponseWriter, resource string, cacheKeyPrefix string) {
	// Check cache first before doing any lookups
	key := fmt.Sprintf("%s%s", cacheKeyPrefix, resource)
	cacheResult, err := utils.GetFromCache(ctx, config.CacheManager, key)
	if err != nil {
		utils.HandleInternalError(ctx, w, err)
		return
	}
	if cacheResult.Found {
		w.Header().Set("X-Cache", "HIT")
		if utils.IsNegativeCacheHit(w, cacheResult.Data) {
			return
		}
		setCacheControl(w)
		utils.HandleCacheResponse(w, cacheResult.Data, "application/json")
		return
	}

	// Parse the IP and find the RDAP server URL
	ip := net.ParseIP(resource)
	serverURL, _ := serverlist.LookupIPKey(ip)

	// Query and parse the RDAP information, deduplicating concurrent misses
	outcome, err := dedupedQuery(ctx, key, func(qctx context.Context) (queryOutcome, error) {
		queryResult, err := rdap.RDAPQueryIP(qctx, resource, serverURL)
		if err != nil {
			return queryOutcome{}, err
		}

		ipInfo, err := rdap.ParseRDAPResponseforIP(queryResult)
		if err != nil {
			return queryOutcome{}, err
		}

		resultBytes, err := json.Marshal(ipInfo)
		if err != nil {
			return queryOutcome{}, err
		}

		result := string(resultBytes)
		if err := utils.SetToCache(qctx, config.CacheManager, key, result, config.CacheExpiration); err != nil {
			slog.WarnContext(qctx, "cache write error", "key", key, "err", err)
		}
		return queryOutcome{body: result, contentType: "application/json"}, nil
	})
	if err != nil {
		utils.HandleQueryError(ctx, w, err)
		return
	}

	// Return the RDAP information
	w.Header().Set("X-Cache", "MISS")
	setCacheControl(w)
	w.Header().Set("Content-Type", outcome.contentType)
	_, _ = fmt.Fprint(w, outcome.body)
}
