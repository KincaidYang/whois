package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/rdap"
	"github.com/KincaidYang/whois/internal/serverlist"
	"github.com/KincaidYang/whois/internal/utils"
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
		utils.HandleHTTPError(w, utils.ErrorTypeBadRequest, "Invalid ASN format")
		return
	}

	// Check cache first before doing any lookups
	key := fmt.Sprintf("%s%s", cacheKeyPrefix, asn)
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

	// Find the RDAP server URL via pre-built sorted ASN range index
	serverURL, _ := serverlist.LookupASNKey(asnInt)

	// Query and parse the RDAP information, deduplicating concurrent misses
	outcome, err := dedupedQuery(ctx, key, func(qctx context.Context) (queryOutcome, error) {
		queryResult, err := rdap.RDAPQueryASN(qctx, asn, serverURL)
		if err != nil {
			return queryOutcome{}, err
		}

		asnInfo, err := rdap.ParseRDAPResponseforASN(queryResult)
		if err != nil {
			return queryOutcome{}, err
		}

		resultBytes, err := json.Marshal(asnInfo)
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
