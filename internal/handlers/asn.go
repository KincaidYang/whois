package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/KincaidYang/whois/internal/rdap"
	"github.com/KincaidYang/whois/internal/serverlist"
	"github.com/KincaidYang/whois/internal/utils"
)

// HandleASN function is used to handle the HTTP request for querying the RDAP information for a given ASN (Autonomous System Number).
// When refresh is true the cache read is skipped: the query goes upstream and
// its result overwrites the cached entry (X-Cache: REFRESH).
func HandleASN(ctx context.Context, w http.ResponseWriter, resource string, cacheKeyPrefix string, refresh bool) {
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
	if serveFromCache(ctx, w, key, refresh) != cacheMiss {
		return
	}

	// Find the RDAP server URL via pre-built sorted ASN range index
	serverURL, _ := serverlist.LookupASNKey(asnInt)

	// Query and parse the RDAP information, deduplicating concurrent misses
	outcome, err := dedupedQuery(ctx, key, refresh, func(qctx context.Context) (queryOutcome, error) {
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

		return queryOutcome{body: string(resultBytes), contentType: "application/json"}, nil
	})
	if err != nil {
		utils.HandleQueryError(ctx, w, err)
		return
	}

	// Return the RDAP information
	writeUpstreamResult(w, outcome, refresh)
}
