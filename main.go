package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
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

// 将 whois 报文转换为DomainInfo结构体
var whoisParsers = map[string]func(string, string) (DomainInfo, error){
	"cn":          parseWhoisResponseCN,
	"hk":          parseWhoisResponseHK,
	"xn--j6w193g": parseWhoisResponseHK,
	"co":          parseWhoisResponseCO,
	// ...为其他 TLD 添加解析函数...
}

var (
	// 用于限制并发请求数的缓冲通道
	concurrencyLimiter = make(chan struct{}, 50) // 限制最多同时处理 50 个请求

	// 用于缓存查询结果的
	domainCache = cache.New(5*time.Minute, 10*time.Minute)

	// http.Client 用于设置 rdapQuery 的超时时间
	httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}
)

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
							domainInfo.Registrar = vcardArray.([]interface{})[1].([]interface{})[1].([]interface{})[3].(string)
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
		if delegationSigned, ok := secureDNS.(map[string]interface{})["delegationSigned"]; ok && delegationSigned.(bool) {
			domainInfo.DNSSec = "signedDelegation"
			if dsData, ok := secureDNS.(map[string]interface{})["dsData"].([]interface{}); ok && len(dsData) > 0 {
				dsDataInfo := dsData[0].(map[string]interface{})
				domainInfo.DNSSecDSData = fmt.Sprintf("%d %d %d %s",
					int(dsDataInfo["keyTag"].(float64)),
					int(dsDataInfo["algorithm"].(float64)),
					int(dsDataInfo["digestType"].(float64)),
					dsDataInfo["digest"].(string),
				)
			}
		}
	}

	return domainInfo, nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/")

	// 将域名转换为小写
	domain = strings.ToLower(domain)

	// 将域名转换为 Punycode 编码（支持 IDN 域名）
	punycodeDomain, err := idna.ToASCII(domain)
	if err != nil {
		http.Error(w, "Invalid domain name: "+domain, http.StatusBadRequest)
		return
	}
	domain = punycodeDomain

	// 使用 publicsuffix 库获取顶级域
	tld, _ := publicsuffix.PublicSuffix(domain)

	// 如果结果不符合预期（例如 "com.cn"），则从右向左读取域名，将第一个点右边的部分作为 TLD
	if strings.Contains(tld, ".") {
		parts := strings.Split(domain, ".")
		tld = parts[len(parts)-1]
	}

	// 从缓存中获取查询结果
	if result, found := domainCache.Get(domain); found {
		log.Printf("Serving cached result for domain: %s\n", domain)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, result)
		return
	}

	concurrencyLimiter <- struct{}{} // 请求并发限制
	defer func() { <-concurrencyLimiter }()

	var result string

	if _, ok := tldToRdapServer[tld]; ok {
		result, err = rdapQuery(domain, tld)
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
		domainInfo, err := parseRDAPResponse(result)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resultBytes, err := json.Marshal(domainInfo)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		result = string(resultBytes)
		w.Header().Set("Content-Type", "application/json")

	} else if _, ok := tldToWhoisServer[tld]; ok {
		result, err = whois(domain, tld)
		if err == nil {
			// 使用 TLD 对应的解析函数解析 WHOIS 数据
			if parseFunc, ok := whoisParsers[tld]; ok {
				domainInfo, err := parseFunc(result, domain)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				resultBytes, err := json.Marshal(domainInfo)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				result = string(resultBytes)
				w.Header().Set("Content-Type", "application/json")
			} else {
				// 如果没有可用的解析规则，返回原始 WHOIS 数据
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			}
		}
	} else {
		http.Error(w, "No WHOIS or RDAP server known for TLD: "+tld, http.StatusInternalServerError)
		return
	}

	// 将查询结果存入缓存
	domainCache.Set(domain, result, 5*time.Minute)

	fmt.Fprint(w, result)
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Server is listening on port 8080...")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("Server failed to start:", err)
		os.Exit(1)
	}
}
