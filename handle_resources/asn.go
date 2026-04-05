package handle_resources

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/KincaidYang/whois/config"
	"github.com/KincaidYang/whois/rdap_tools"
	"github.com/KincaidYang/whois/server_lists"
	"github.com/KincaidYang/whois/utils"
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
		utils.HandleInternalError(w, err)
		return
	}
	if cacheResult.Found {
		utils.HandleCacheResponse(w, cacheResult.Data, "application/json")
		return
	}

	// Find the RDAP server URL via pre-built sorted ASN range index
	serverURL, _ := server_lists.LookupASNKey(asnInt)

	// Query the RDAP information for the ASN
	queryresult, err := rdap_tools.RDAPQueryASN(ctx, asn, serverURL)
	if err != nil {
		utils.HandleQueryError(w, err)
		return
	}

	// Parse the RDAP response
	asnInfo, err := rdap_tools.ParseRDAPResponseforASN(queryresult)
	if err != nil {
		utils.HandleInternalError(w, err)
		return
	}

	// Marshal the result to JSON
	resultBytes, err := json.Marshal(asnInfo)
	if err != nil {
		utils.HandleInternalError(w, err)
		return
	}

	// Cache the RDAP information
	err = utils.SetToCache(ctx, config.CacheManager, key, string(resultBytes), config.CacheExpiration)
	if err != nil {
		slog.Warn("cache write error", "key", key, "err", err)
	}

	// Return the RDAP information
	w.Header().Set("Content-Type", "application/json")
	w.Write(resultBytes)
}
