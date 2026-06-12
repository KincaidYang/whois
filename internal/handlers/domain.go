package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/model"
	"github.com/KincaidYang/whois/internal/rdap"
	"github.com/KincaidYang/whois/internal/serverlist"
	"github.com/KincaidYang/whois/internal/utils"
	"github.com/KincaidYang/whois/internal/whois"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// CacheKeyPrefix namespaces all cache entries. The version segment is bumped
// whenever the response format changes, so entries cached by an older release
// are never served in the old format after an upgrade.
const CacheKeyPrefix = "whois:v1:"

// finalizeDomainInfo fills the fields shared by every domain response that
// the parsers cannot know themselves: the Unicode form of the name (IDN) and
// non-nil slices so the JSON contains [] instead of null.
func finalizeDomainInfo(info *model.DomainInfo, domain string) {
	if info.LdhName == "" {
		info.LdhName = domain
	}
	if info.UnicodeName == "" {
		if u, err := idna.ToUnicode(info.LdhName); err == nil {
			info.UnicodeName = u
		}
	}
	if info.Status == nil {
		info.Status = []string{}
	}
	if info.Nameservers == nil {
		info.Nameservers = []string{}
	}
}

// whoisParsers is a map from top-level domain (TLD) to a function that can parse
// the WHOIS response for that TLD into a DomainInfo structure.
// Currently, it includes parsers for the following TLDs: cn, xn--fiqs8s, xn--fiqz9s,
// hk, xn--j6w193g, tw, so, sb, sg, mo, ru, su, au, la, jp, eu, xn--e1a4c,
// xn--qxa6a, kr, xn--3e0b707e.
// You can add parsers for other TLDs by adding them to this map.
var whoisParsers = map[string]func(string, string) (model.DomainInfo, error){
	"cn":           whois.ParseWhoisResponseCN,
	"xn--fiqs8s":   whois.ParseWhoisResponseCN,
	"xn--fiqz9s":   whois.ParseWhoisResponseCN,
	"hk":           whois.ParseWhoisResponseHK,
	"xn--j6w193g":  whois.ParseWhoisResponseHK,
	"tw":           whois.ParseWhoisResponseTW,
	"so":           whois.ParseWhoisResponseSO,
	"sb":           whois.ParseWhoisResponseSB,
	"sg":           whois.ParseWhoisResponseSG,
	"mo":           whois.ParseWhoisResponseMO,
	"ru":           whois.ParseWhoisResponseRU,
	"su":           whois.ParseWhoisResponseRU,
	"au":           whois.ParseWhoisResponseAU,
	"la":           whois.ParseWhoisResponseLA,
	"jp":           whois.ParseWhoisResponseJP,
	"eu":           whois.ParseWhoisResponseEU,
	"xn--e1a4c":    whois.ParseWhoisResponseEU,
	"xn--qxa6a":    whois.ParseWhoisResponseEU,
	"kr":           whois.ParseWhoisResponseKR,
	"xn--3e0b707e": whois.ParseWhoisResponseKR,
}

// HandleDomain function is used to handle the HTTP request for querying the RDAP (Registration Data Access Protocol) or WHOIS information for a given domain.
// When raw is true, the unparsed WHOIS response is returned as text/plain
// (RDAP is skipped, since RDAP has no raw-text form), cached under a separate
// "raw:" key namespace so parsed and raw results never mix.
// When refresh is true the cache read is skipped: the query goes upstream and
// its result overwrites the cached entry (X-Cache: REFRESH).
func HandleDomain(ctx context.Context, w http.ResponseWriter, resource string, cacheKeyPrefix string, raw, refresh bool) {
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
		_, hasWhoisServer := serverlist.TLDToWhoisServer[tld]
		_, hasRdapServer := serverlist.LookupRdapServer(tld)
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
	if !refresh {
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
			contentType := "application/json"
			if len(cacheResult.Data) == 0 || cacheResult.Data[0] != '{' {
				contentType = "text/plain; charset=utf-8"
			}
			setCacheControl(w)
			utils.HandleCacheResponse(w, cacheResult.Data, contentType)
			return
		}
	}

	// Select the query path: RDAP preferred, WHOIS as fallback (raw output
	// always queries WHOIS). The query itself runs deduplicated, so
	// concurrent misses on the same domain share one upstream request.
	var query func(context.Context) (queryOutcome, error)
	if raw {
		if _, ok := serverlist.TLDToWhoisServer[tld]; !ok {
			utils.HandleHTTPError(w, utils.ErrorTypeNotFound, "No WHOIS server known for TLD: "+tld)
			return
		}
		query = func(qctx context.Context) (queryOutcome, error) {
			return queryWhoisRaw(qctx, domain, tld, key)
		}
	} else if _, ok := serverlist.LookupRdapServer(tld); ok {
		query = func(qctx context.Context) (queryOutcome, error) {
			return queryRDAPDomain(qctx, domain, tld, key)
		}
	} else if _, ok := serverlist.TLDToWhoisServer[tld]; ok {
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

	w.Header().Set("X-Cache", missLabel(refresh))
	setCacheControl(w)
	w.Header().Set("Content-Type", outcome.contentType)
	_, _ = fmt.Fprint(w, outcome.body)
}

// queryRDAPDomain queries RDAP for a domain, parses the response, and caches
// the result.
func queryRDAPDomain(ctx context.Context, domain, tld, key string) (queryOutcome, error) {
	queryResult, err := rdap.RDAPQuery(ctx, domain, tld)
	if err != nil {
		return queryOutcome{}, err
	}

	domainInfo, err := rdap.ParseRDAPResponseforDomain(queryResult)
	if err != nil {
		return queryOutcome{}, err
	}
	finalizeDomainInfo(&domainInfo, domain)

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
	queryResult, err := whois.Whois(ctx, domain, tld)
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
	queryResult, err := whois.Whois(ctx, domain, tld)
	if err != nil {
		return queryOutcome{}, err
	}

	parseFunc, ok := whoisParsers[tld]
	if !ok {
		// No parser for this TLD: wrap the raw WHOIS text in the regular JSON
		// object (unparsed=true) so the endpoint's content type stays stable.
		// Clients that want the bare text use ?raw=1.
		info := model.DomainInfo{
			ObjectClassName: model.ObjectClassDomain,
			Unparsed:        true,
			RawText:         queryResult,
		}
		finalizeDomainInfo(&info, domain)
		resultBytes, err := json.Marshal(info)
		if err != nil {
			return queryOutcome{}, err
		}
		result := string(resultBytes)
		if err := utils.SetToCache(ctx, config.CacheManager, key, result, config.CacheExpiration); err != nil {
			slog.WarnContext(ctx, "cache write error", "key", key, "err", err)
		}
		return queryOutcome{body: result, contentType: "application/json"}, nil
	}

	var domainInfo model.DomainInfo
	domainInfo, err = parseFunc(queryResult, domain)
	if err != nil {
		// "resource not found" or other parsing error during the WHOIS parsing
		return queryOutcome{}, err
	}
	finalizeDomainInfo(&domainInfo, domain)

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
