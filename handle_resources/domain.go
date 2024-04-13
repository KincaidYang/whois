package handle_resources

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/KincaidYang/whois/config"
	"github.com/KincaidYang/whois/rdap_tools"
	"github.com/KincaidYang/whois/rdap_tools/structs"
	"github.com/KincaidYang/whois/server_lists"
	"github.com/KincaidYang/whois/whois_tools"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// whoisParsers is a map from top-level domain (TLD) to a function that can parse
// the WHOIS response for that TLD into a DomainInfo structure.
// Currently, it includes parsers for the following TLDs: cn, xn--fiqs8s, xn--fiqz9s,
// hk, xn--j6w193g, tw, so, sb, sg, mo, ru, su, au.
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
}

// HandleDomain function is used to handle the HTTP request for querying the RDAP (Registration Data Access Protocol) or WHOIS information for a given domain.
func HandleDomain(ctx context.Context, w http.ResponseWriter, resource string, cacheKeyPrefix string) {
	// Convert the domain to Punycode encoding (supports IDN domains)
	punycodeDomain, err := idna.ToASCII(resource)
	if err != nil {
		http.Error(w, "Invalid domain name: "+resource, http.StatusBadRequest)
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
	cacheResult, err := config.RedisClient.Get(ctx, key).Result()

	// Check if the RDAP or WHOIS information for the domain is cached in Redis
	if err == nil {
		log.Printf("Serving cached result for resource: %s\n", domain)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, cacheResult)
		return
	} else if err != redis.Nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var queryResult string

	// If the RDAP server for the TLD is known, query the RDAP information for the domain
	if _, ok := server_lists.TLDToRdapServer[tld]; ok {
		queryResult, err = rdap_tools.RDAPQuery(domain, tld)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			if err.Error() == "resource not found" {
				w.WriteHeader(http.StatusNotFound) // Set the status code to 404
				fmt.Fprint(w, `{"error": "Resource not found"}`)
			} else if err.Error() == "the registry denied the query" {
				w.WriteHeader(http.StatusForbidden) // Set the status code to 403
				fmt.Fprint(w, `{"error": "The registry denied the query"}`)
			} else {
				w.WriteHeader(http.StatusInternalServerError) // Set the status code to 500
				fmt.Fprint(w, `{"error": "`+err.Error()+`"}`)
			}
			return
		}
		domainInfo, err := rdap_tools.ParseRDAPResponseforDomain(queryResult)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resultBytes, err := json.Marshal(domainInfo)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		queryResult = string(resultBytes)
		err = config.RedisClient.Set(ctx, key, queryResult, config.CacheExpiration).Err()
		if err != nil {
			log.Printf("Failed to cache result for resource: %s\n", resource)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, queryResult)

		// If the WHOIS server for the TLD is known, query the WHOIS information for the domain
	} else if _, ok := server_lists.TLDToWhoisServer[tld]; ok {
		queryResult, err = whois_tools.Whois(domain, tld)
		if err != nil {
			// If there's a network or other error during the WHOIS query
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"error": "`+err.Error()+`"}`)
			return
		}

		// Use the parsing function corresponding to the TLD to parse the WHOIS data
		var domainInfo structs.DomainInfo
		if parseFunc, ok := whoisParsers[tld]; ok {
			domainInfo, err = parseFunc(queryResult, domain)
			if err != nil {
				// If there's a "resource not found" or other parsing error during the WHOIS parsing
				if err.Error() == "domain not found" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound) // Set the status code to 404
					fmt.Fprint(w, `{"error": "resource not found"}`)
				} else {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
				return
			}

			resultBytes, err := json.Marshal(domainInfo)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			queryResult = string(resultBytes)
			err = config.RedisClient.Set(ctx, key, queryResult, config.CacheExpiration).Err()
			if err != nil {
				log.Printf("Failed to cache result for resource: %s\n", resource)
			}
			w.Header().Set("Content-Type", "application/json")
		} else {
			// If there's no available parsing rule, return the original WHOIS data and set the response type to text/plain
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			err = config.RedisClient.Set(ctx, key, queryResult, config.CacheExpiration).Err()
			if err != nil {
				log.Printf("Failed to cache result for resource: %s\n", resource)
			}
		}

		fmt.Fprint(w, queryResult)
	} else {
		http.Error(w, "No WHOIS or RDAP server known for TLD: "+tld, http.StatusInternalServerError)
		return
	}
}
