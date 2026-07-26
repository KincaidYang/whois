package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/KincaidYang/whois/internal/rdap"
	"github.com/KincaidYang/whois/internal/serverlist"
	"github.com/KincaidYang/whois/internal/utils"
)

// HandleIP function is used to handle the HTTP request for querying the RDAP information for a given IP.
// When refresh is true the cache read is skipped: the query goes upstream and
// its result overwrites the cached entry (X-Cache: REFRESH).
func HandleIP(ctx context.Context, w http.ResponseWriter, resource string, cacheKeyPrefix string, refresh bool) {
	// Check cache first before doing any lookups
	key := fmt.Sprintf("%s%s", cacheKeyPrefix, resource)
	if serveFromCache(ctx, w, key, refresh) != cacheMiss {
		return
	}

	// Parse the IP (for CIDR input, the prefix base address) and find the
	// RDAP server URL
	ipStr := resource
	if i := strings.IndexByte(resource, '/'); i >= 0 {
		ipStr = resource[:i]
	}
	ip := net.ParseIP(ipStr)
	serverURL, _ := serverlist.LookupIPKey(ip)

	// Query and parse the RDAP information, deduplicating concurrent misses
	outcome, err := dedupedQuery(ctx, key, refresh, func(qctx context.Context) (queryOutcome, error) {
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

		return queryOutcome{body: string(resultBytes), contentType: "application/json"}, nil
	})
	if err != nil {
		utils.HandleQueryError(ctx, w, err)
		return
	}

	// Return the RDAP information
	writeUpstreamResult(w, outcome, refresh)
}
