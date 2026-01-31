package handle_resources

import (
	"context"
	"encoding/json"
	"fmt"
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
// hk, xn--j6w193g, tw, so, sb, sg, mo, ru, su, au, la.
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
}

// HandleDomain function is used to handle the HTTP request for querying the RDAP (Registration Data Access Protocol) or WHOIS information for a given domain.
func HandleDomain(ctx context.Context, w http.ResponseWriter, resource string, cacheKeyPrefix string) {
	// Convert the domain to Punycode encoding (supports IDN domains)
	punycodeDomain, err := idna.ToASCII(resource)
	if err != nil {
		utils.HandleHTTPError(w, utils.ErrorTypeBadRequest, "Invalid domain name: "+resource)
		return
	}
	resource = punycodeDomain

	// Get the TLD (Top-Level Domain) of the domain
	tld, _ := publicsuffix.PublicSuffix(resource)

	// If the TLD is not as expected (e.g., "com.cn"), read the domain from right to left and take the part to the right of the first dot as the TLD
	if strings.Contains(tld, ".") {
		parts := strings.Split(tld, ".")
		tld = parts[len(parts)-1]
	}

	// Get the main domain
	mainDomain, _ := publicsuffix.EffectiveTLDPlusOne(resource)
	if mainDomain == "" {
		mainDomain = resource
	}
	resource = mainDomain
	domain := resource
	key := fmt.Sprintf("%s%s", cacheKeyPrefix, domain)

	// Check if the RDAP or WHOIS information for the domain is cached
	cacheResult, err := utils.GetFromCache(ctx, config.CacheManager, key)
	if err != nil {
		utils.HandleInternalError(w, err)
		return
	}

	if cacheResult.Found {
		utils.HandleCacheResponse(w, cacheResult.Data, "application/json")
		return
	}

	var queryResult string

	// If the RDAP server for the TLD is known, query the RDAP information for the domain
	if _, ok := server_lists.TLDToRdapServer[tld]; ok {
		queryResult, err = handleRDAPQuery(ctx, w, domain, tld, key)
		if err != nil {
			return // Error already handled in function
		}
	} else if _, ok := server_lists.TLDToWhoisServer[tld]; ok {
		// If the WHOIS server for the TLD is known, query the WHOIS information for the domain
		queryResult, err = handleWhoisQuery(ctx, w, domain, tld, key)
		if err != nil {
			return // Error already handled in function
		}
	} else {
		utils.HandleHTTPError(w, utils.ErrorTypeInternalServer, "No WHOIS or RDAP server known for TLD: "+tld)
		return
	}

	fmt.Fprint(w, queryResult)
}

// handleRDAPQuery handles RDAP queries for domains
func handleRDAPQuery(ctx context.Context, w http.ResponseWriter, domain, tld, key string) (string, error) {
	queryResult, err := rdap_tools.RDAPQuery(domain, tld)
	if err != nil {
		utils.HandleQueryError(w, err)
		return "", err
	}

	domainInfo, err := rdap_tools.ParseRDAPResponseforDomain(queryResult)
	if err != nil {
		utils.HandleInternalError(w, err)
		return "", err
	}

	resultBytes, err := json.Marshal(domainInfo)
	if err != nil {
		utils.HandleInternalError(w, err)
		return "", err
	}

	queryResult = string(resultBytes)

	// Cache the result
	err = utils.SetToCache(ctx, config.CacheManager, key, queryResult, config.CacheExpiration)
	if err != nil {
		// Log the error but don't fail the request
	}

	w.Header().Set("Content-Type", "application/json")
	return queryResult, nil
}

// handleWhoisQuery handles WHOIS queries for domains
func handleWhoisQuery(ctx context.Context, w http.ResponseWriter, domain, tld, key string) (string, error) {
	queryResult, err := whois_tools.Whois(domain, tld)
	if err != nil {
		// If there's a network or other error during the WHOIS query
		utils.HandleHTTPError(w, utils.ErrorTypeInternalServer, err.Error())
		return "", err
	}

	// Use the parsing function corresponding to the TLD to parse the WHOIS data
	var domainInfo structs.DomainInfo
	if parseFunc, ok := whoisParsers[tld]; ok {
		domainInfo, err = parseFunc(queryResult, domain)
		if err != nil {
			// If there's a "resource not found" or other parsing error during the WHOIS parsing
			utils.HandleQueryError(w, err)
			return "", err
		}

		resultBytes, err := json.Marshal(domainInfo)
		if err != nil {
			utils.HandleInternalError(w, err)
			return "", err
		}
		queryResult = string(resultBytes)

		// Cache the result
		err = utils.SetToCache(ctx, config.CacheManager, key, queryResult, config.CacheExpiration)
		if err != nil {
			// Log the error but don't fail the request
		}

		w.Header().Set("Content-Type", "application/json")
	} else {
		// If there's no available parsing rule, return the original WHOIS data and set the response type to text/plain
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		err = utils.SetToCache(ctx, config.CacheManager, key, queryResult, config.CacheExpiration)
		if err != nil {
			// Log the error but don't fail the request
		}
	}

	return queryResult, nil
}
