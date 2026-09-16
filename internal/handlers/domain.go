package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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

// icannSuffix returns the nearest ICANN-section public suffix at or above
// name's PSL suffix, climbing past any private-section entry (e.g.
// blogspot.com, github.io) until it reaches one the registry itself
// operates. A name whose PSL suffix isn't in the list at all (an unknown
// TLD: icann=false with no further label to climb) is returned unchanged —
// there's nothing more authoritative to climb to.
func icannSuffix(name string) string {
	suffix, icann := publicsuffix.PublicSuffix(name)
	for !icann && strings.Contains(suffix, ".") {
		suffix = suffix[strings.Index(suffix, ".")+1:]
		suffix, icann = publicsuffix.PublicSuffix(suffix)
	}
	return suffix
}

// registrableDomain returns the label of name immediately above tld, plus
// tld itself — the registrable name at that suffix. name equal to tld (the
// suffix queried on its own, with nothing above it) is returned unchanged.
func registrableDomain(name, tld string) string {
	if name == tld {
		return name
	}
	prefix := strings.TrimSuffix(name, "."+tld)
	if prefix == name {
		// tld wasn't actually a suffix of name; shouldn't happen given tld
		// is derived from name itself, but leave name unchanged rather than
		// fail the request over it.
		return name
	}
	if i := strings.LastIndex(prefix, "."); i >= 0 {
		prefix = prefix[i+1:]
	}
	return prefix + "." + tld
}

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

	// Get the TLD (Top-Level Domain) of the domain, for parser/server
	// selection below. This intentionally uses the raw PSL suffix, private
	// section included: the compound-TLD fallback right below already
	// degrades any multi-label result without a dedicated entry down to its
	// last label regardless of why it's compound, so a private-section
	// suffix like "blogspot.com" degrades to "com" the same way a
	// non-dedicated ICANN one would.
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

	// Get the main domain: the registrable name one label above the nearest
	// ICANN-section public suffix — not the PSL "effective TLD" as such,
	// which is what publicsuffix.EffectiveTLDPlusOne would use. The PSL's
	// private section lists entries like blogspot.com or github.io as if
	// they were TLDs, so EffectiveTLDPlusOne("test.blogspot.com") returns
	// "test.blogspot.com" itself — a subdomain the registry has never heard
	// of, not the object actually registered with it (blogspot.com).
	// icannSuffix climbs private-section results up to the nearest ICANN one
	// (blogspot.com -> com, myblog.github.io -> io) to find the real
	// registry boundary; for an already-ICANN suffix (including compound
	// ones like co.jp) it's a no-op and this matches EffectiveTLDPlusOne
	// exactly, so ordinary domains are unaffected.
	resource = registrableDomain(resource, icannSuffix(resource))
	domain := resource
	key := fmt.Sprintf("%s%s", cacheKeyPrefix, domain)
	if raw {
		key = fmt.Sprintf("%sraw:%s", cacheKeyPrefix, domain)
	}

	// Check if the RDAP or WHOIS information for the domain is cached
	if serveFromCache(ctx, w, key, refresh) != cacheMiss {
		return
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
			return queryWhoisRaw(qctx, domain, tld)
		}
	} else if _, ok := serverlist.LookupRdapServer(tld); ok {
		query = func(qctx context.Context) (queryOutcome, error) {
			return queryRDAPDomain(qctx, domain, tld)
		}
	} else if _, ok := serverlist.TLDToWhoisServer[tld]; ok {
		query = func(qctx context.Context) (queryOutcome, error) {
			return queryWhoisDomain(qctx, domain, tld)
		}
	} else {
		// Nothing to query for this TLD: that is an answer about the requested
		// resource, not a server-side failure, so it must not be reported as
		// one (the ?raw path above answers the same way).
		utils.HandleHTTPError(w, utils.ErrorTypeNotFound, "No WHOIS or RDAP server known for TLD: "+tld)
		return
	}

	outcome, err := dedupedQuery(ctx, key, refresh, query)
	if err != nil {
		utils.HandleQueryError(ctx, w, err)
		return
	}

	writeUpstreamResult(w, outcome, refresh)
}

// queryRDAPDomain queries RDAP for a domain and parses the response.
func queryRDAPDomain(ctx context.Context, domain, tld string) (queryOutcome, error) {
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

	return queryOutcome{body: string(resultBytes), contentType: "application/json"}, nil
}

// queryWhoisRaw queries WHOIS for a domain and returns the unparsed response
// as text/plain.
func queryWhoisRaw(ctx context.Context, domain, tld string) (queryOutcome, error) {
	queryResult, err := whois.Whois(ctx, domain, tld)
	if err != nil {
		return queryOutcome{}, err
	}

	return queryOutcome{body: queryResult, contentType: "text/plain; charset=utf-8"}, nil
}

// queryWhoisDomain queries WHOIS for a domain, parsing the response when a
// parser exists for the TLD (raw text otherwise).
func queryWhoisDomain(ctx context.Context, domain, tld string) (queryOutcome, error) {
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
		return queryOutcome{body: string(resultBytes), contentType: "application/json"}, nil
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

	return queryOutcome{body: string(resultBytes), contentType: "application/json"}, nil
}
