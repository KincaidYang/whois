package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	server_lists "github.com/KincaidYang/whois/server_lists"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// DomainInfo represents the information about a domain.
type DomainInfo struct {
	DomainName         string   `json:"Domain Name"`             // DomainName is the name of the domain.
	Registrar          string   `json:"Registrar"`               // Registrar is the registrar of the domain.
	RegistrarIANAID    string   `json:"Registrar IANA ID"`       // RegistrarIANAID is the IANA ID of the registrar.
	DomainStatus       []string `json:"Domain Status"`           // DomainStatus is the status of the domain.
	CreationDate       string   `json:"Creation Date"`           // CreationDate is the creation date of the domain.
	RegistryExpiryDate string   `json:"Registry Expiry Date"`    // RegistryExpiryDate is the expiry date of the domain.
	UpdatedDate        string   `json:"Updated Date"`            // UpdatedDate is the updated date of the domain.
	NameServer         []string `json:"Name Server"`             // NameServer is the name server of the domain.
	DNSSec             string   `json:"DNSSEC"`                  // DNSSec is the DNSSEC of the domain.
	DNSSecDSData       string   `json:"DNSSEC DS Data"`          // DNSSecDSData is the DNSSEC DS Data of the domain.
	LastUpdateOfRDAPDB string   `json:"Last Update of Database"` // LastUpdateOfRDAPDB is the last update of the database.
}

// ASNInfo represents the information about an Autonomous System Number (ASN).
type ASNInfo struct {
	ASN          string   `json:"AS Number"`     // ASN is the Autonomous System Number.
	ASName       string   `json:"Network Name"`  // ASName is the name of the network.
	ASStatus     []string `json:"Status"`        // ASStatus is the status of the ASN.
	CreationDate string   `json:"Creation Date"` // CreationDate is the creation date of the ASN.
	UpdatedDate  string   `json:"Updated Date"`  // UpdatedDate is the updated date of the ASN.
}

// IPInfo represents the information about an IP network.
type IPInfo struct {
	IP           string   `json:"IP Network"`    // IP is the IP network.
	Range        string   `json:"Address Range"` // Range is the address range of the IP network.
	NetName      string   `json:"Network Name"`  // NetName is the name of the network.
	CIDR         string   `json:"CIDR"`          // CIDR is the CIDR of the IP network.
	Networktype  string   `json:"Network Type"`  // Networktype is the type of the network.
	Country      string   `json:"Country"`       // Country is the country of the IP network.
	IPStatus     []string `json:"Status"`        // IPStatus is the status of the IP network.
	CreationDate string   `json:"Creation Date"` // CreationDate is the creation date of the IP network.
	UpdatedDate  string   `json:"Updated Date"`  // UpdatedDate is the updated date of the IP network.
}

// Config represents the configuration for the application.
type Config struct {
	// Redis holds the configuration for the Redis database.
	// It includes the address, password, and database number.
	Redis struct {
		Addr     string `json:"addr"`     // Addr is the address of the Redis server.
		Password string `json:"password"` // Password is the password for the Redis server.
		DB       int    `json:"db"`       // DB is the database number for the Redis server.
	} `json:"redis"`
	// CacheExpiration is the expiration time for the cache, in seconds.
	CacheExpiration int `json:"cacheExpiration"`
	// Port is the port number for the server.
	Port int `json:"port"`
	// RateLimit is the maximum number of requests that a client can make in a specified period of time.
	RateLimit int `json:"rateLimit"`
}

// whoisParsers is a map from top-level domain (TLD) to a function that can parse
// the WHOIS response for that TLD into a DomainInfo structure.
// Currently, it includes parsers for the following TLDs: cn, xn--fiqs8s, xn--fiqz9s,
// hk, xn--j6w193g, tw, so, sb, sg, mo, ru, su, au.
// You can add parsers for other TLDs by adding them to this map.
var whoisParsers = map[string]func(string, string) (DomainInfo, error){
	"cn":          parseWhoisResponseCN,
	"xn--fiqs8s":  parseWhoisResponseCN,
	"xn--fiqz9s":  parseWhoisResponseCN,
	"hk":          parseWhoisResponseHK,
	"xn--j6w193g": parseWhoisResponseHK,
	"tw":          parseWhoisResponseTW,
	"so":          parseWhoisResponseSO,
	"sb":          parseWhoisResponseSB,
	"sg":          parseWhoisResponseSG,
	"mo":          parseWhoisResponseMO,
	"ru":          parseWhoisResponseRU,
	"su":          parseWhoisResponseRU,
	"au":          parseWhoisResponseAU,
}

var (
	// redisClient is the Redis client
	redisClient *redis.Client
	// cacheExpiration is the cache duration
	cacheExpiration time.Duration
	// httpClient is used to set the timeout for rdapQuery
	httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}
	// wg is used to wait for all goroutines to finish
	wg sync.WaitGroup
	// port is used to set the port the server listens on
	port int
	// rateLimit is used to set the number of concurrent requests
	rateLimit          int
	concurrencyLimiter chan struct{}
)

func init() {
	var config Config

	// Open the configuration file
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("Failed to open configuration file: %v", err)
	}
	defer configFile.Close()

	// Decode the configuration file
	decoder := json.NewDecoder(configFile)
	err = decoder.Decode(&config)
	if err != nil {
		log.Fatalf("Failed to decode JSON from configuration file: %v", err)
	}

	// Initialize the Redis client
	redisClient = redis.NewClient(&redis.Options{
		Addr:     config.Redis.Addr,
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})

	// Set the cache expiration time
	cacheExpiration = time.Duration(config.CacheExpiration) * time.Second

	// Set the port the server listens on
	port = config.Port

	// Set the number of concurrent requests
	rateLimit = config.RateLimit
	concurrencyLimiter = make(chan struct{}, rateLimit)
}

// whois function is used to query the WHOIS information for a given domain.
func whois(domain, tld string) (string, error) {
	whoisServer, ok := server_lists.TLDToWhoisServer[tld]
	if !ok {
		return "", fmt.Errorf("no Whois server known for TLD: %s", tld)
	}

	// Log the request for the WHOIS query
	log.Printf("Querying WHOIS for domain: %s with TLD: %s on server: %s\n", domain, tld, whoisServer)

	conn, err := net.Dial("tcp", whoisServer+":43")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.Write([]byte(domain + "\r\n"))
	var buf bytes.Buffer
	_, err = io.Copy(&buf, conn)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// rdapQuery function is used to query the RDAP (Registration Data Access Protocol) information for a given domain.
func rdapQuery(domain, tld string) (string, error) {
	rdapServer, ok := server_lists.TLDToRdapServer[tld]
	if !ok {
		return "", fmt.Errorf("no RDAP server known for TLD: %s", tld)
	}

	// Log the request for the RDAP query
	log.Printf("Querying RDAP for domain: %s with TLD: %s on server: %s\n", domain, tld, rdapServer)

	req, err := http.NewRequest("GET", rdapServer+"domain/"+domain, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", errors.New("domain not found")
	} else if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// 本来是没打算写域名之外的查询的，所以变量名看着像域名很正常，不想改了QAQ
// rdapQueryIP function is used to query the RDAP information for a given IP address.
func rdapQueryIP(ip, tld string) (string, error) {
	rdapServer, ok := server_lists.TLDToRdapServer[tld]
	if !ok {
		return "", fmt.Errorf("no RDAP server known for IP: %s", ip)
	}

	// Log the request for the RDAP query
	log.Printf("Querying RDAP for IP: %s with TLD: %s on server: %s\n", ip, tld, rdapServer)

	req, err := http.NewRequest("GET", rdapServer+"ip/"+ip, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", errors.New("resource not found")
	} else if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// rdapQueryASN function is used to query the RDAP information for a given ASN.
func rdapQueryASN(as, tld string) (string, error) {
	rdapServer, ok := server_lists.TLDToRdapServer[tld]
	if !ok {
		return "", fmt.Errorf("no RDAP server known for ASN: %s", as)
	}

	// Log the request for the RDAP query
	log.Printf("Querying RDAP for AS: %s with TLD: %s on server: %s\n", as, tld, rdapServer)

	req, err := http.NewRequest("GET", rdapServer+"autnum/"+as, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", errors.New("resource not found")
	} else if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// parseRDAPResponse function is used to parse the RDAP response for a given domain.
func parseRDAPResponse(response string) (DomainInfo, error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(response), &result)
	if err != nil {
		return DomainInfo{}, err
	}

	domainInfo := DomainInfo{}

	if ldhName, ok := result["ldhName"]; ok {
		domainInfo.DomainName = ldhName.(string)
	}

	if status, ok := result["status"]; ok {
		domainInfo.DomainStatus = make([]string, len(status.([]interface{})))
		for i, s := range status.([]interface{}) {
			domainInfo.DomainStatus[i] = s.(string)
		}
	}

	if entities, ok := result["entities"]; ok {
		for _, entity := range entities.([]interface{}) {
			if roles, ok := entity.(map[string]interface{})["roles"]; ok {
				for _, role := range roles.([]interface{}) {
					if role.(string) == "registrar" {
						registrarEntity := entity.(map[string]interface{})
						if vcardArray, ok := registrarEntity["vcardArray"]; ok {
							vcardArraySlice, ok := vcardArray.([]interface{})
							if ok && len(vcardArraySlice) > 1 {
								innerSlice, ok := vcardArraySlice[1].([]interface{})
								if ok {
									for _, item := range innerSlice {
										itemSlice, ok := item.([]interface{})
										if ok && len(itemSlice) > 0 {
											if itemSlice[0] == "fn" && len(itemSlice) > 3 {
												domainInfo.Registrar = itemSlice[3].(string)
												break
											}
										}
									}
								}
							}
						}
						if publicIds, ok := registrarEntity["publicIds"]; ok {
							domainInfo.RegistrarIANAID = publicIds.([]interface{})[0].(map[string]interface{})["identifier"].(string)
						}
						break
					}
				}
			}
		}
	}

	if events, ok := result["events"]; ok {
		for _, event := range events.([]interface{}) {
			eventInfo := event.(map[string]interface{})
			switch eventInfo["eventAction"].(string) {
			case "registration":
				domainInfo.CreationDate = eventInfo["eventDate"].(string)
			case "expiration":
				domainInfo.RegistryExpiryDate = eventInfo["eventDate"].(string)
			case "last changed":
				domainInfo.UpdatedDate = eventInfo["eventDate"].(string)
			case "last update of RDAP database":
				domainInfo.LastUpdateOfRDAPDB = eventInfo["eventDate"].(string)
			}
		}
	}

	if nameservers, ok := result["nameservers"]; ok {
		domainInfo.NameServer = make([]string, len(nameservers.([]interface{})))
		for i, ns := range nameservers.([]interface{}) {
			domainInfo.NameServer[i] = ns.(map[string]interface{})["ldhName"].(string)
		}
	}

	domainInfo.DNSSec = "unsigned"
	if secureDNS, ok := result["secureDNS"]; ok {
		if dsData, ok := secureDNS.(map[string]interface{})["dsData"].([]interface{}); ok && len(dsData) > 0 {
			dsDataInfo := dsData[0].(map[string]interface{})
			domainInfo.DNSSec = "signedDelegation"
			domainInfo.DNSSecDSData = fmt.Sprintf("%d %d %d %s",
				int(dsDataInfo["keyTag"].(float64)),
				int(dsDataInfo["algorithm"].(float64)),
				int(dsDataInfo["digestType"].(float64)),
				dsDataInfo["digest"].(string),
			)
		} else if keyData, ok := secureDNS.(map[string]interface{})["keyData"].([]interface{}); ok && len(keyData) > 0 {
			keyDataInfo := keyData[0].(map[string]interface{})
			domainInfo.DNSSec = "signedDelegation"
			domainInfo.DNSSecDSData = fmt.Sprintf("%d %d %d %s",
				int(keyDataInfo["algorithm"].(float64)),
				int(keyDataInfo["flags"].(float64)),
				int(keyDataInfo["protocol"].(float64)),
				keyDataInfo["publicKey"].(string),
			)
		}
	}

	return domainInfo, nil
}

// parseWhoisResponseforIP function is used to parse the WHOIS response for an IP address.
func parseRDAPResponseforIP(response string) (IPInfo, error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(response), &result)
	if err != nil {
		return IPInfo{}, err
	}

	ipinfo := IPInfo{}

	if handle, ok := result["handle"]; ok {
		ipinfo.IP = handle.(string)
	}

	if startAddress, ok := result["startAddress"]; ok {
		ipinfo.Range = startAddress.(string)
	}

	if endAddress, ok := result["endAddress"]; ok {
		ipinfo.Range += " - " + endAddress.(string)
	}

	if name, ok := result["name"]; ok {
		ipinfo.NetName = name.(string)
	}

	if cidrs, ok := result["cidr0_cidrs"]; ok {
		for _, cidr := range cidrs.([]interface{}) {
			cidrMap := cidr.(map[string]interface{})
			if v4prefix, ok := cidrMap["v4prefix"]; ok {
				length := cidrMap["length"].(float64)
				ipinfo.CIDR = fmt.Sprintf("%s/%d", v4prefix.(string), int(length))
			} else if v6prefix, ok := cidrMap["v6prefix"]; ok {
				length := cidrMap["length"].(float64)
				ipinfo.CIDR = fmt.Sprintf("%s/%d", v6prefix.(string), int(length))
			}
		}
	}

	if type_, ok := result["type"]; ok && type_ != nil {
		ipinfo.Networktype = type_.(string)
	} else {
		ipinfo.Networktype = "Unknown"
	}

	if country, ok := result["country"]; ok {
		ipinfo.Country = country.(string)
	}

	if status, ok := result["status"]; ok {
		ipinfo.IPStatus = make([]string, len(status.([]interface{})))
		for i, s := range status.([]interface{}) {
			ipinfo.IPStatus[i] = s.(string)
		}
	}

	if events, ok := result["events"]; ok {
		for _, event := range events.([]interface{}) {
			eventInfo := event.(map[string]interface{})
			switch eventInfo["eventAction"].(string) {
			case "registration":
				ipinfo.CreationDate = eventInfo["eventDate"].(string)
			case "last changed":
				ipinfo.UpdatedDate = eventInfo["eventDate"].(string)
			}
		}
	}
	return ipinfo, nil
}

// parseRDAPResponseforASN function is used to parse the RDAP response for an ASN.
func parseRDAPResponseforASN(response string) (ASNInfo, error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(response), &result)
	if err != nil {
		return ASNInfo{}, err
	}

	asninfo := ASNInfo{}

	if handle, ok := result["handle"]; ok {
		asninfo.ASN = handle.(string)
	}

	if name, ok := result["name"]; ok {
		asninfo.ASName = name.(string)
	}

	if status, ok := result["status"]; ok {
		asninfo.ASStatus = make([]string, len(status.([]interface{})))
		for i, s := range status.([]interface{}) {
			asninfo.ASStatus[i] = s.(string)
		}
	}

	if events, ok := result["events"]; ok {
		for _, event := range events.([]interface{}) {
			eventInfo := event.(map[string]interface{})
			switch eventInfo["eventAction"].(string) {
			case "registration":
				asninfo.CreationDate = eventInfo["eventDate"].(string)
			case "last changed":
				asninfo.UpdatedDate = eventInfo["eventDate"].(string)
			}
		}
	}
	return asninfo, nil
}

// handleIP function is used to handle the HTTP request for querying the RDAP information for a given IP.
func handleIP(ctx context.Context, w http.ResponseWriter, resource string, cacheKeyPrefix string) {
	// Parse the IP
	ip := net.ParseIP(resource)

	// Find the corresponding TLD from the TLDToRdapServer map
	var tld string
	for cidr := range server_lists.TLDToRdapServer {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// If the key cannot be parsed as a CIDR, skip this key
			continue
		}

		if ipNet.Contains(ip) {
			tld = cidr
			break
		}
	}

	// Check if the RDAP information for the IP is cached in Redis
	key := fmt.Sprintf("%s%s", cacheKeyPrefix, resource)
	cacheResult, err := redisClient.Get(ctx, key).Result()
	if err == nil {
		// If the RDAP information is cached, return the cached result
		log.Printf("Serving cached result for resource: %s\n", resource)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, cacheResult)
		return
	} else if err != redis.Nil {
		// If there's an error during caching, return an HTTP error
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Query the RDAP information for the IP
	queryresult, err := rdapQueryIP(resource, tld)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if errors.Is(err, errors.New("resource not found")) {
			w.WriteHeader(http.StatusOK) // Set the status code to 200
			fmt.Fprint(w, `{"error": "Resource not found"}`)
		} else {
			w.WriteHeader(http.StatusOK) // Set the status code to 200
			fmt.Fprint(w, `{"error": "`+err.Error()+`"}`)
		}
		return
	}

	// Parse the RDAP response
	ipInfo, err := parseRDAPResponseforIP(queryresult)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Cache the RDAP information in Redis
	resultBytes, err := json.Marshal(ipInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	queryResult := string(resultBytes)
	err = redisClient.Set(ctx, key, queryResult, cacheExpiration).Err()
	if err != nil {
		log.Printf("Failed to cache result for resource: %s\n", resource)
	}

	// Return the RDAP information
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, queryResult)
}

// handleASN function is used to handle the HTTP request for querying the RDAP information for a given ASN (Autonomous System Number).
func handleASN(ctx context.Context, w http.ResponseWriter, resource string, cacheKeyPrefix string) {
	// Parse the ASN
	asn := strings.TrimPrefix(resource, "asn")
	if asn == resource {
		asn = strings.TrimPrefix(resource, "as")
	}
	asnInt, err := strconv.Atoi(asn)
	if err != nil {
		// handle error
		return
	}

	// Generate the cache key
	key := fmt.Sprintf("%s%s", cacheKeyPrefix, asn)

	// Check if the RDAP information for the ASN is cached in Redis
	cacheResult, err := redisClient.Get(ctx, key).Result()
	if err == nil {
		// If the RDAP information is cached, return the cached result
		log.Printf("Serving cached result for resource: %s\n", asn)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, cacheResult)
		return
	} else if err != redis.Nil {
		// If there's an error during caching, return an HTTP error
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Find the corresponding TLD from the TLDToRdapServer map
	var tld string
	for rangeStr := range server_lists.TLDToRdapServer {
		if !strings.Contains(rangeStr, "-") {
			continue
		}
		rangeParts := strings.Split(rangeStr, "-")
		if len(rangeParts) != 2 {
			continue
		}
		lower, err := strconv.Atoi(rangeParts[0])
		if err != nil {
			continue
		}
		upper, err := strconv.Atoi(rangeParts[1])
		if err != nil {
			continue
		}
		if asnInt >= lower && asnInt <= upper {
			tld = rangeStr
			break
		}
	}

	// Query the RDAP information for the ASN
	queryresult, err := rdapQueryASN(asn, tld)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if errors.Is(err, errors.New("resource not found")) {
			w.WriteHeader(http.StatusOK) // Set the status code to 200
			fmt.Fprint(w, `{"error": "Resource not found"}`)
		} else {
			w.WriteHeader(http.StatusOK) // Set the status code to 200
			fmt.Fprint(w, `{"error": "`+err.Error()+`"}`)
		}
		return
	}

	// Parse the RDAP response
	asnInfo, err := parseRDAPResponseforASN(queryresult)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Cache the RDAP information in Redis
	resultBytes, err := json.Marshal(asnInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	queryResult := string(resultBytes)
	err = redisClient.Set(ctx, key, queryResult, cacheExpiration).Err()
	if err != nil {
		log.Printf("Failed to cache result for resource: %s\n", resource)
	}

	// Return the RDAP information
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, queryResult)
}

// handleDomain function is used to handle the HTTP request for querying the RDAP (Registration Data Access Protocol) or WHOIS information for a given domain.
func handleDomain(ctx context.Context, w http.ResponseWriter, resource string, cacheKeyPrefix string) {
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
	cacheResult, err := redisClient.Get(ctx, key).Result()

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
		queryResult, err = rdapQuery(domain, tld)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			if errors.Is(err, errors.New("domain not found")) {
				w.WriteHeader(http.StatusOK) // Set the status code to 200
				fmt.Fprint(w, `{"error": "Domain not found"}`)
			} else {
				w.WriteHeader(http.StatusOK) // Set the status code to 200
				fmt.Fprint(w, `{"error": "`+err.Error()+`"}`)
			}
			return
		}
		domainInfo, err := parseRDAPResponse(queryResult)
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
		err = redisClient.Set(ctx, key, queryResult, cacheExpiration).Err()
		if err != nil {
			log.Printf("Failed to cache result for resource: %s\n", resource)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, queryResult)

		// If the WHOIS server for the TLD is known, query the WHOIS information for the domain
	} else if _, ok := server_lists.TLDToWhoisServer[tld]; ok {
		queryResult, err = whois(domain, tld)
		if err != nil {
			// If there's a network or other error during the WHOIS query
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"error": "`+err.Error()+`"}`)
			return
		}

		// Use the parsing function corresponding to the TLD to parse the WHOIS data
		var domainInfo DomainInfo
		if parseFunc, ok := whoisParsers[tld]; ok {
			domainInfo, err = parseFunc(queryResult, domain)
			if err != nil {
				// If there's a "domain not found" or other parsing error during the WHOIS parsing
				if err.Error() == "domain not found" {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, `{"error": "domain not found"}`)
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
			err = redisClient.Set(ctx, key, queryResult, cacheExpiration).Err()
			if err != nil {
				log.Printf("Failed to cache result for resource: %s\n", resource)
			}
			w.Header().Set("Content-Type", "application/json")
		} else {
			// If there's no available parsing rule, return the original WHOIS data and set the response type to text/plain
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			err = redisClient.Set(ctx, key, queryResult, cacheExpiration).Err()
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

// isASN function is used to check if the given resource is an Autonomous System Number (ASN).
func isASN(resource string) bool {
	return regexp.MustCompile(`^(as|asn)\d+$`).MatchString(resource) || regexp.MustCompile(`^\d+$`).MatchString(resource)
}

func handler(w http.ResponseWriter, r *http.Request) {
	if len(concurrencyLimiter) == rateLimit {
		log.Printf("Rate limit reached, waiting for a slot to become available...\n")
	}
	concurrencyLimiter <- struct{}{}
	wg.Add(1)
	defer func() {
		wg.Done()
		<-concurrencyLimiter
	}()

	ctx := context.Background()
	resource := strings.TrimPrefix(r.URL.Path, "/")
	resource = strings.ToLower(resource)

	cacheKeyPrefix := "whois:"

	if net.ParseIP(resource) != nil {
		handleIP(ctx, w, resource, cacheKeyPrefix)
	} else if isASN(resource) {
		handleASN(ctx, w, resource, cacheKeyPrefix)
	} else {
		handleDomain(ctx, w, resource, cacheKeyPrefix)
	}

}

func checkRedisConnection() {
	ctx := context.Background()
	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}
}

func main() {
	// Check Redis Connection
	checkRedisConnection()

	http.HandleFunc("/", handler)
	go func() {
		fmt.Printf("Server is listening on port %d...\n", port)
		err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
		if err != nil {
			fmt.Println("Server failed to start:", err)
			os.Exit(1)
		}
	}()

	// Add a signal listener. When a shutdown signal is received, wait for all queries to complete before shutting down the server.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Received shutdown signal, waiting for all queries to complete...")
	wg.Wait()

	log.Println("All queries completed. Shutting down server...")
	redisClient.Close()
	os.Exit(0)
}
