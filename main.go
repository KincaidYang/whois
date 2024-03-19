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

	"github.com/redis/go-redis/v9"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type DomainInfo struct {
	DomainName         string   `json:"Domain Name"`
	Registrar          string   `json:"Registrar"`
	RegistrarIANAID    string   `json:"Registrar IANA ID"`
	DomainStatus       []string `json:"Domain Status"`
	CreationDate       string   `json:"Creation Date"`
	RegistryExpiryDate string   `json:"Registry Expiry Date"`
	UpdatedDate        string   `json:"Updated Date"`
	NameServer         []string `json:"Name Server"`
	DNSSec             string   `json:"DNSSEC"`
	DNSSecDSData       string   `json:"DNSSEC DS Data"`
	LastUpdateOfRDAPDB string   `json:"Last Update of Database"`
}

type ASNInfo struct {
	ASN          string   `json:"AS Number"`
	ASName       string   `json:"Network Name"`
	ASStatus     []string `json:"Status"`
	CreationDate string   `json:"Creation Date"`
	UpdatedDate  string   `json:"Updated Date"`
}

type IPInfo struct {
	IP           string   `json:"IP Network"`
	Range        string   `json:"Address Range"`
	NetName      string   `json:"Network Name"`
	CIDR         string   `json:"CIDR"`
	Networktype  string   `json:"Network Type"`
	Country      string   `json:"Country"`
	IPStatus     []string `json:"Status"`
	CreationDate string   `json:"Creation Date"`
	UpdatedDate  string   `json:"Updated Date"`
}

type Config struct {
	Redis struct {
		Addr     string `json:"addr"`
		Password string `json:"password"`
		DB       int    `json:"db"`
	} `json:"redis"`
	CacheExpiration int `json:"cacheExpiration"`
	Port            int `json:"port"`
	RateLimit       int `json:"rateLimit"`
}

// 将 whois 报文转换为DomainInfo结构体
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
	// 为其他 TLD 添加解析函数
}

var (
	// Redis 客户端
	redisClient *redis.Client
	// 缓存时间
	cacheExpiration time.Duration
	// http.Client 用于设置 rdapQuery 的超时时间
	httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}
	// WaitGroup 用于等待所有 goroutine 结束
	wg sync.WaitGroup
	// Port 用于设置服务器监听的端口
	port int
	// RateLimit 用于设置并发请求数
	rateLimit          int
	concurrencyLimiter chan struct{}
)

func init() {
	var config Config

	// 读取配置文件
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("Failed to open configuration file: %v", err)
	}
	defer configFile.Close()

	// 解析配置文件
	decoder := json.NewDecoder(configFile)
	err = decoder.Decode(&config)
	if err != nil {
		log.Fatalf("Failed to decode JSON from configuration file: %v", err)
	}

	// 初始化 Redis 客户端
	redisClient = redis.NewClient(&redis.Options{
		Addr:     config.Redis.Addr,
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})

	// 设置缓存过期时间
	cacheExpiration = time.Duration(config.CacheExpiration) * time.Second

	// 设置服务器监听的端口
	port = config.Port

	// 设置并发请求数
	rateLimit = config.RateLimit
	concurrencyLimiter = make(chan struct{}, rateLimit)
}

func whois(domain, tld string) (string, error) {
	whoisServer, ok := tldToWhoisServer[tld]
	if !ok {
		return "", fmt.Errorf("no Whois server known for TLD: %s", tld)
	}

	// 记录 WHOIS 查询时的请求日志
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

func rdapQuery(domain, tld string) (string, error) {
	rdapServer, ok := tldToRdapServer[tld]
	if !ok {
		return "", fmt.Errorf("no RDAP server known for TLD: %s", tld)
	}

	// 记录 RDAP 查询时的请求日志
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
func rdapQueryIP(ip, tld string) (string, error) {
	rdapServer, ok := tldToRdapServer[tld]
	if !ok {
		return "", fmt.Errorf("no RDAP server known for IP: %s", ip)
	}

	// 记录 RDAP 查询时的请求日志
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
func rdapQueryASN(as, tld string) (string, error) {
	rdapServer, ok := tldToRdapServer[tld]
	if !ok {
		return "", fmt.Errorf("no RDAP server known for ASN: %s", as)
	}

	// 记录 RDAP 查询时的请求日志
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

func handler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	resource := strings.TrimPrefix(r.URL.Path, "/")
	resource = strings.ToLower(resource)

	cacheKeyPrefix := "whois:"

	if net.ParseIP(resource) != nil {
		ip := net.ParseIP(resource)
		var tld string
		for cidr := range tldToRdapServer {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				// 如果不能解析为 CIDR，跳过此键
				continue
			}

			if ipNet.Contains(ip) {
				tld = cidr
				break
			}
		}
		key := fmt.Sprintf("%s%s", cacheKeyPrefix, resource)
		cacheResult, err := redisClient.Get(ctx, key).Result()
		if err == nil {
			log.Printf("Serving cached result for resource: %s\n", resource)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, cacheResult)
			return
		} else if err != redis.Nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		queryresult, err := rdapQueryIP(resource, tld)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			if errors.Is(err, errors.New("resource not found")) {
				w.WriteHeader(http.StatusOK) // 设置状态码为 200
				fmt.Fprint(w, `{"error": "Resource not found"}`)
			} else {
				w.WriteHeader(http.StatusOK) // 设置状态码为 200
				fmt.Fprint(w, `{"error": "`+err.Error()+`"}`)
			}
			return
		}
		ipInfo, err := parseRDAPResponseforIP(queryresult)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, queryResult)
	} else if regexp.MustCompile(`^(as|asn)\d+$`).MatchString(resource) || regexp.MustCompile(`^\d+$`).MatchString(resource) {
		asn := strings.TrimPrefix(resource, "asn")
		if asn == resource {
			asn = strings.TrimPrefix(resource, "as")
		}
		asnInt, err := strconv.Atoi(asn)
		if err != nil {
			// handle error
			return
		}

		key := fmt.Sprintf("%s%s", cacheKeyPrefix, asn)
		cacheResult, err := redisClient.Get(ctx, key).Result()
		if err == nil {
			log.Printf("Serving cached result for resource: %s\n", asn)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, cacheResult)
			return
		} else if err != redis.Nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var tld string
		for rangeStr := range tldToRdapServer {
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
		queryresult, err := rdapQueryASN(asn, tld)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			if errors.Is(err, errors.New("resource not found")) {
				w.WriteHeader(http.StatusOK) // 设置状态码为 200
				fmt.Fprint(w, `{"error": "Resource not found"}`)
			} else {
				w.WriteHeader(http.StatusOK) // 设置状态码为 200
				fmt.Fprint(w, `{"error": "`+err.Error()+`"}`)
			}
			return
		}
		asnInfo, err := parseRDAPResponseforASN(queryresult)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, queryResult)
	} else {
		// 将域名转换为 Punycode 编码（支持 IDN 域名）
		punycodeDomain, err := idna.ToASCII(resource)
		if err != nil {
			http.Error(w, "Invalid domain name: "+resource, http.StatusBadRequest)
			return
		}
		resource = punycodeDomain

		// 使用 publicsuffix 库获取顶级域，这部分代码其实可以省略，因为要获取顶级域，单单靠下面的代码从右向左读取域名，取第一个点右边的部分即可
		tld, _ := publicsuffix.PublicSuffix(resource)

		// 如果结果不符合预期（例如 "com.cn"），则从右向左读取域名，将第一个点右边的部分作为 TLD
		if strings.Contains(tld, ".") {
			parts := strings.Split(tld, ".")
			tld = parts[len(parts)-1]
		}

		// 获取主域名
		mainDomain, _ := publicsuffix.EffectiveTLDPlusOne(resource)
		if mainDomain == "" {
			mainDomain = resource
		}
		resource = mainDomain
		domain := resource
		key := fmt.Sprintf("%s%s", cacheKeyPrefix, domain)
		cacheResult, err := redisClient.Get(ctx, key).Result()

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

		if _, ok := tldToRdapServer[tld]; ok {
			queryResult, err = rdapQuery(domain, tld)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				if errors.Is(err, errors.New("domain not found")) {
					w.WriteHeader(http.StatusOK) // 设置状态码为 200
					fmt.Fprint(w, `{"error": "Domain not found"}`)
				} else {
					w.WriteHeader(http.StatusOK) // 设置状态码为 200
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

		} else if _, ok := tldToWhoisServer[tld]; ok {
			queryResult, err = whois(domain, tld)
			if err != nil {
				// 当 WHOIS 查询过程中的网络或其他错误
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"error": "`+err.Error()+`"}`)
				return
			}

			// 使用 TLD 对应的解析函数解析 WHOIS 数据
			var domainInfo DomainInfo
			if parseFunc, ok := whoisParsers[tld]; ok {
				domainInfo, err = parseFunc(queryResult, domain)
				if err != nil {
					// 当 WHOIS 解析过程中发现“域名未找到”或其他解析错误
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
				// 如果没有可用的解析规则，直接返回原始 WHOIS 数据，并设置响应类型为 text/plain
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

	if len(concurrencyLimiter) == rateLimit {
		log.Printf("Rate limit reached, waiting for a slot to become available...\n")
	}
	concurrencyLimiter <- struct{}{} // 请求并发限制
	wg.Add(1)
	defer func() {
		wg.Done()
		<-concurrencyLimiter
	}()
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

	// 增加一个信号监听，当接收到关闭信号时，先等待所有查询完成，再关闭服务器
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Received shutdown signal, waiting for all queries to complete...")
	wg.Wait()

	log.Println("All queries completed. Shutting down server...")
	redisClient.Close()
	os.Exit(0)
}
