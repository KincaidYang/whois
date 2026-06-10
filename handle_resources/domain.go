package handle_resources

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/KincaidYang/whois/config"
	"github.com/KincaidYang/whois/rdap_tools"
	"github.com/KincaidYang/whois/rdap_tools/structs"
	"github.com/KincaidYang/whois/server_lists"
	"github.com/KincaidYang/whois/utils"
	"github.com/KincaidYang/whois/whois_tools"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// whoisParsers is a map from top-level domain (TLD) to a function that can parse
// the WHOIS response for that TLD into a DomainInfo structure.
// Currently, it includes parsers for the following TLDs: cn, xn--fiqs8s, xn--fiqz9s,
// hk, xn--j6w193g, tw, so, sb, sg, mo, ru, su, au, la, jp.
// You can add parsers for other TLDs by adding them to this map.
var whoisParsers = map[string]func(string, string) (structs.DomainInfo, error){
	"cn":          whois_tools.ParseWhoisResponseCN,
	"xn--fiqs8s":  whois_tools.ParseWhoisResponseCN,
	"xn--fiqz9s":  whois_tools.ParseWhoisResponseCN,
	"hk":          whois_tools.ParseWhoisResponseHK,
	"xn--j6w193g": whois_tools.ParseWhoisResponseHK,
	"tw":          whois_tools.ParseWhoisResponseTW,
	"so":          whois_tools.ParseWhoisResponseSO,
	"sb":          whois_tools.ParseWhoisResponseSB,
	"sg":          whois_tools.ParseWhoisResponseSG,
	"mo":          whois_tools.ParseWhoisResponseMO,
	"ru":          whois_tools.ParseWhoisResponseRU,
	"su":          whois_tools.ParseWhoisResponseRU,
	"au":          whois_tools.ParseWhoisResponseAU,
	"la":          whois_tools.ParseWhoisResponseLA,
	"jp":          whois_tools.ParseWhoisResponseJP,
}

// HandleDomain function is used to handle the HTTP request for querying the RDAP (Registration Data Access Protocol) or WHOIS information for a given domain.
// When raw is true, the unparsed WHOIS response is returned as text/plain
// (RDAP is skipped, since RDAP has no raw-text form), cached under a separate
// "raw:" key namespace so parsed and raw results never mix.
func HandleDomain(ctx context.Context, w http.ResponseWriter, resource string, cacheKeyPrefix string, raw bool) {
	// Convert the domain to Punycode encoding (supports IDN domains)
	punycodeDomain, err := idna.ToASCII(resource)
	if err != nil {
		utils.HandleHTTPError(w, utils.ErrorTypeBadRequest, "Invalid domain name: "+resource)
		return
	}
	resource = punycodeDomain

	// Get the TLD (Top-Level Domain) of the domain
	tld, _ := publicsuffix.PublicSuffix(resource)

	// For compound TLDs like "co.jp", check if we have a dedicated parser or server.
	// Otherwise, fall back to the root TLD (e.g., "jp").
	if strings.Contains(tld, ".") {
		_, hasParser := whoisParsers[tld]
		_, hasWhoisServer := server_lists.TLDToWhoisServer[tld]
		_, hasRdapServer := server_lists.LookupRdapServer(tld)
		if !hasParser && !hasWhoisServer && !hasRdapServer {
			parts := strings.Split(tld, ".")
			tld = parts[len(parts)-1]
		}
	}

	// Get the main domain
	mainDomain, _ := publicsuffix.EffectiveTLDPlusOne(resource)
	if mainDomain == "" {
		mainDomain = resource
	}
	resource = mainDomain
	domain := resource
	key := fmt.Sprintf("%s%s", cacheKeyPrefix, domain)
	if raw {
		key = fmt.Sprintf("%sraw:%s", cacheKeyPrefix, domain)
	}

	// Check if the RDAP or WHOIS information for the domain is cached
	cacheResult, err := utils.GetFromCache(ctx, config.CacheManager, key)
	if err != nil {
		utils.HandleInternalError(ctx, w, err)
		return
	}

	if cacheResult.Found {
		if utils.IsNegativeCacheHit(w, cacheResult.Data) {
			return
		}
		contentType := "application/json"
		if len(cacheResult.Data) == 0 || cacheResult.Data[0] != '{' {
			contentType = "text/plain; charset=utf-8"
		}
		utils.HandleCacheResponse(w, cacheResult.Data, contentType)
		return
	}

	// Select the query path: RDAP preferred, WHOIS as fallback (raw output
	// always queries WHOIS). The query itself runs deduplicated, so
	// concurrent misses on the same domain share one upstream request.
	var query func(context.Context) (queryOutcome, error)
	if raw {
		if _, ok := server_lists.TLDToWhoisServer[tld]; !ok {
			utils.HandleHTTPError(w, utils.ErrorTypeNotFound, "No WHOIS server known for TLD: "+tld)
			return
		}
		query = func(qctx context.Context) (queryOutcome, error) {
			return queryWhoisRaw(qctx, domain, tld, key)
		}
	} else if _, ok := server_lists.LookupRdapServer(tld); ok {
		query = func(qctx context.Context) (queryOutcome, error) {
			return queryRDAPDomain(qctx, domain, tld, key)
		}
	} else if _, ok := server_lists.TLDToWhoisServer[tld]; ok {
		query = func(qctx context.Context) (queryOutcome, error) {
			return queryWhoisDomain(qctx, domain, tld, key)
		}
	} else {
		utils.HandleHTTPError(w, utils.ErrorTypeInternalServer, "No WHOIS or RDAP server known for TLD: "+tld)
		return
	}

	outcome, err := dedupedQuery(ctx, key, query)
	if err != nil {
		utils.HandleQueryError(ctx, w, err)
		return
	}

	w.Header().Set("Content-Type", outcome.contentType)
	fmt.Fprint(w, outcome.body)
}

// queryRDAPDomain queries RDAP for a domain, parses the response, and caches
// the result.
func queryRDAPDomain(ctx context.Context, domain, tld, key string) (queryOutcome, error) {
	queryResult, err := rdap_tools.RDAPQuery(ctx, domain, tld)
	if err != nil {
		return queryOutcome{}, err
	}

	domainInfo, err := rdap_tools.ParseRDAPResponseforDomain(queryResult)
	if err != nil {
		return queryOutcome{}, err
	}

	resultBytes, err := json.Marshal(domainInfo)
	if err != nil {
		return queryOutcome{}, err
	}

	result := string(resultBytes)
	if err := utils.SetToCache(ctx, config.CacheManager, key, result, config.CacheExpiration); err != nil {
		slog.WarnContext(ctx, "cache write error", "key", key, "err", err)
	}

	return queryOutcome{body: result, contentType: "application/json"}, nil
}

// queryWhoisRaw queries WHOIS for a domain and caches/returns the unparsed
// response as text/plain.
func queryWhoisRaw(ctx context.Context, domain, tld, key string) (queryOutcome, error) {
	queryResult, err := whois_tools.Whois(ctx, domain, tld)
	if err != nil {
		return queryOutcome{}, err
	}

	if err := utils.SetToCache(ctx, config.CacheManager, key, queryResult, config.CacheExpiration); err != nil {
		slog.WarnContext(ctx, "cache write error", "key", key, "err", err)
	}
	return queryOutcome{body: queryResult, contentType: "text/plain; charset=utf-8"}, nil
}

// queryWhoisDomain queries WHOIS for a domain, parses the response when a
// parser exists for the TLD (raw text otherwise), and caches the result.
func queryWhoisDomain(ctx context.Context, domain, tld, key string) (queryOutcome, error) {
	queryResult, err := whois_tools.Whois(ctx, domain, tld)
	if err != nil {
		return queryOutcome{}, err
	}

	parseFunc, ok := whoisParsers[tld]
	if !ok {
		// If there's no available parsing rule, return the original WHOIS data as text/plain
		if err := utils.SetToCache(ctx, config.CacheManager, key, queryResult, config.CacheExpiration); err != nil {
			slog.WarnContext(ctx, "cache write error", "key", key, "err", err)
		}
		return queryOutcome{body: queryResult, contentType: "text/plain; charset=utf-8"}, nil
	}

	var domainInfo structs.DomainInfo
	domainInfo, err = parseFunc(queryResult, domain)
	if err != nil {
		// "resource not found" or other parsing error during the WHOIS parsing
		return queryOutcome{}, err
	}

	resultBytes, err := json.Marshal(domainInfo)
	if err != nil {
		return queryOutcome{}, err
	}

	result := string(resultBytes)
	if err := utils.SetToCache(ctx, config.CacheManager, key, result, config.CacheExpiration); err != nil {
		slog.WarnContext(ctx, "cache write error", "key", key, "err", err)
	}

	return queryOutcome{body: result, contentType: "application/json"}, nil
}
