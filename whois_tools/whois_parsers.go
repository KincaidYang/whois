package whois_tools

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/KincaidYang/whois/rdap_tools/structs"
)

// JP WHOIS 预编译正则表达式
var (
	// 格式1：.jp 域名
	reJPDomainName = regexp.MustCompile(`\[Domain Name\]\s+(.*)`)
	reJPRegistrant = regexp.MustCompile(`\[Registrant\]\s+(.*)`)
	reJPNameServer = regexp.MustCompile(`\[Name Server\]\s+(\S+)`)
	// 格式2：.co.jp 等变体域名
	reJPDomainNameAlt = regexp.MustCompile(`a\.\s*\[ドメイン名\]\s+(.*)`)
	reJPOrganization  = regexp.MustCompile(`g\.\s*\[Organization\]\s+(.*)`)
	reJPNameServerAlt = regexp.MustCompile(`p\.\s*\[ネームサーバ\]\s+(\S+)`)
	// 通用字段
	reJPCreationDate = regexp.MustCompile(`\[登録年月日\]\s+(.*)`)
	reJPExpiryDate   = regexp.MustCompile(`\[有効期限\]\s+(.*)`)
	reJPStatus       = regexp.MustCompile(`\[状態\]\s+(.*)`)
	reJPLockStatus   = regexp.MustCompile(`\[ロック状態\]\s+(.*)`)
	reJPUpdatedDate  = regexp.MustCompile(`\[最終更新\]\s+(.*)`)
	// 工具正则
	reJPExpiryInStatus = regexp.MustCompile(`\((\d{4}/\d{2}/\d{2})\)`)
	reJPTimezone       = regexp.MustCompile(`\s*\([A-Z]+\)\s*$`)
	reMultiSpace       = regexp.MustCompile(`\s+`)
)

func ParseWhoisResponseCN(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// 使用正则表达式匹配 WHOIS 数据中的相关信息
	reCreationDate := regexp.MustCompile(`Registration Time: (.*)`)
	reExpiryDate := regexp.MustCompile(`Expiration Time: (.*)`)
	reNameServer := regexp.MustCompile(`Name Server: (.*)`)
	reDNSSEC := regexp.MustCompile(`DNSSEC: (.*)`)
	reRegistrar := regexp.MustCompile(`Sponsoring Registrar: (.*)`)
	reDomainStatus := regexp.MustCompile(`Domain Status: (.*)`)

	// 解析创建日期
	matchCreationDate := reCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		// 解析原始时间字符串
		t, err := time.Parse("2006-01-02 15:04:05", matchCreationDate[1])
		if err != nil {
			return structs.DomainInfo{}, err
		}
		// 将时间转换为 UTC，并格式化为新的字符串
		domainInfo.CreationDate = t.Add(-8 * time.Hour).Format(time.RFC3339Nano)
	}

	// 解析过期日期
	matchExpiryDate := reExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		// 解析原始时间字符串
		t, err := time.Parse("2006-01-02 15:04:05", matchExpiryDate[1])
		if err != nil {
			return structs.DomainInfo{}, err
		}
		// 将时间转换为 UTC，并格式化为新的字符串
		domainInfo.RegistryExpiryDate = t.Add(-8 * time.Hour).Format(time.RFC3339Nano)
	}

	// 解析名称服务器
	matchNameServers := reNameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.NameServer = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.NameServer[i] = match[1]
		}
	}

	// 解析 DNSSEC
	matchDNSSEC := reDNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.DNSSec = matchDNSSEC[1]
	}

	// 解析注册商
	matchRegistrar := reRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = matchRegistrar[1]
	}

	// 解析域名状态
	matchDomainStatuses := reDomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.DomainStatus = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.DomainStatus[i] = match[1]
		}
	}

	// 设置数据库更新时间为数据处理时间
	now := time.Now().UTC().Format(time.RFC3339)
	domainInfo.LastUpdateOfRDAPDB = now

	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return structs.DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}
func ParseWhoisResponseHK(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// 使用正则表达式匹配 WHOIS 数据中的相关信息
	reCreationDate := regexp.MustCompile(`Domain Name Commencement Date: (.*)`)
	reExpiryDate := regexp.MustCompile(`Expiry Date: (.*)`)
	reNameServer := regexp.MustCompile(`Name Servers Information:\s*\n\n((?:.+\n)+)`)
	reDNSSEC := regexp.MustCompile(`DNSSEC: (.*)`)
	reRegistrar := regexp.MustCompile(`Registrar Name: (.*)`)
	reDomainStatus := regexp.MustCompile(`Domain Status: (.*)`)

	// 解析创建日期
	matchCreationDate := reCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		CreationDate := strings.TrimSpace(matchCreationDate[1])
		parsedDate, err := time.Parse("02-01-2006", CreationDate)
		if err == nil {
			domainInfo.CreationDate = parsedDate.Format("2006-01-02")
		}
	}

	// 解析过期日期
	matchExpiryDate := reExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		expiryDate := strings.TrimSpace(matchExpiryDate[1])
		parsedDate, err := time.Parse("02-01-2006", expiryDate)
		if err == nil {
			domainInfo.RegistryExpiryDate = parsedDate.Format("2006-01-02")
		}
	}

	// 解析名称服务器
	matchNameServers := reNameServer.FindStringSubmatch(response)
	if len(matchNameServers) > 1 {
		nameServers := strings.Split(strings.TrimSpace(matchNameServers[1]), "\n")
		domainInfo.NameServer = make([]string, len(nameServers))
		for i, ns := range nameServers {
			domainInfo.NameServer[i] = strings.TrimSpace(ns)
		}
	}

	// 解析 DNSSEC
	matchDNSSEC := reDNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.DNSSec = strings.TrimSpace(matchDNSSEC[1])
	}

	// 解析注册商
	matchRegistrar := reRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = matchRegistrar[1]
	}

	// 解析域名状态
	matchDomainStatus := reDomainStatus.FindStringSubmatch(response)
	if len(matchDomainStatus) > 1 {
		domainInfo.DomainStatus = []string{strings.TrimSpace(matchDomainStatus[1])}
	}

	// 设置数据库更新时间为数据处理时间
	now := time.Now().UTC().Format(time.RFC3339)
	domainInfo.LastUpdateOfRDAPDB = now

	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return structs.DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}

func ParseWhoisResponseTW(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// 使用正则表达式匹配 WHOIS 数据中的相关信息
	reRegistrar := regexp.MustCompile(`Registration Service Provider: (.*)`)
	reDomainStatus := regexp.MustCompile(`Domain Status: (.*)`)
	reCreationDate := regexp.MustCompile(`Record created on ([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})`)
	reExpiryDate := regexp.MustCompile(`Record expires on ([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})`)
	reNameServer := regexp.MustCompile(`(?s)Domain servers in listed order:\n\s+(.*?)\n\n`)
	reDNSSEC := regexp.MustCompile(`DNSSEC: (.*)`)

	// 解析注册商
	matchRegistrar := reRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = strings.TrimSpace(matchRegistrar[1])
	}

	// 解析域名状态
	matchDomainStatuses := reDomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.DomainStatus = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.DomainStatus[i] = strings.TrimSpace(match[1])
		}
	}

	// 解析创建日期
	matchCreationDate := reCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		t, err := time.Parse("2006-01-02 15:04:05", matchCreationDate[1])
		if err != nil {
			return structs.DomainInfo{}, err
		}
		// 将时间转换为 UTC，并格式化为新的字符串
		domainInfo.CreationDate = t.Add(-8 * time.Hour).Format(time.RFC3339Nano)
	}

	// 解析过期日期
	matchExpiryDate := reExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		t, err := time.Parse("2006-01-02 15:04:05", matchExpiryDate[1])
		if err != nil {
			return structs.DomainInfo{}, err
		}
		// 将时间转换为 UTC，并格式化为新的字符串
		domainInfo.RegistryExpiryDate = t.Add(-8 * time.Hour).Format(time.RFC3339Nano)
	}

	// 解析名称服务器
	matchNameServers := reNameServer.FindStringSubmatch(response)
	if len(matchNameServers) > 1 {
		servers := strings.Split(strings.TrimSpace(matchNameServers[1]), "\n")
		domainInfo.NameServer = make([]string, len(servers))
		for i, server := range servers {
			domainInfo.NameServer[i] = strings.TrimSpace(server)
		}
	}

	// 解析 DNSSEC
	matchDNSSEC := reDNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.DNSSec = matchDNSSEC[1]
	}

	// 设置数据库更新时间为数据处理时间
	now := time.Now().UTC().Format(time.RFC3339)
	domainInfo.LastUpdateOfRDAPDB = now

	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return structs.DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}
func ParseWhoisResponseSO(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// 使用正则表达式匹配 WHOIS 数据中的相关信息
	reRegistrar := regexp.MustCompile(`Registrar: (.*)`)
	reDomainStatus := regexp.MustCompile(`Domain Status: (.*)`)
	reUpdatedDate := regexp.MustCompile(`Updated Date: (.*)`)
	reRegistrarIANAID := regexp.MustCompile(`Registrar IANA ID: (.*)`)
	reCreationDate := regexp.MustCompile(`Creation Date: (.*)`)
	reExpiryDate := regexp.MustCompile(`Registry Expiry Date: (.*)`)
	reNameServer := regexp.MustCompile(`Name Server: (.*)`)
	reDNSSEC := regexp.MustCompile(`DNSSEC: (.*)`)
	reDNSSecDSData := regexp.MustCompile(`DNSSEC DS Data: (.*)`)
	reLastUpdateOfRDAPDB := regexp.MustCompile(`Last update of WHOIS database: (.*)`)

	// 解析注册商
	matchRegistrar := reRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = matchRegistrar[1]
	}

	// 解析域名状态
	matchDomainStatuses := reDomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.DomainStatus = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.DomainStatus[i] = match[1]
		}
	}

	// 解析 Registrar IANA ID
	matchRegistrarIANAID := reRegistrarIANAID.FindStringSubmatch(response)
	if len(matchRegistrarIANAID) > 1 {
		domainInfo.RegistrarIANAID = matchRegistrarIANAID[1]
	}

	// 解析创建日期
	matchCreationDate := reCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.CreationDate = matchCreationDate[1]
	}

	// 解析过期日期
	matchExpiryDate := reExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.RegistryExpiryDate = matchExpiryDate[1]
	}

	// 解析更新日期
	matchUpdatedDate := reUpdatedDate.FindStringSubmatch(response)
	if len(matchUpdatedDate) > 1 {
		domainInfo.UpdatedDate = matchUpdatedDate[1]
	}

	// 解析名称服务器
	matchNameServers := reNameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.NameServer = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.NameServer[i] = match[1]
		}
	}

	// 解析 DNSSEC
	matchDNSSEC := reDNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.DNSSec = matchDNSSEC[1]
	}

	// 解析 DNSSEC DS Data
	matchDNSSecDSData := reDNSSecDSData.FindStringSubmatch(response)
	if len(matchDNSSecDSData) > 1 {
		domainInfo.DNSSecDSData = []string{matchDNSSecDSData[1]}
	}

	// 解析数据库更新时间
	matchLastUpdateOfRDAPDB := reLastUpdateOfRDAPDB.FindStringSubmatch(response)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		domainInfo.LastUpdateOfRDAPDB = strings.TrimSuffix(matchLastUpdateOfRDAPDB[1], " \u003c\u003c\u003c")
	}

	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return structs.DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}
func ParseWhoisResponseRU(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// 使用正则表达式匹配 WHOIS 数据中的相关信息
	reRegistrar := regexp.MustCompile(`registrar: (.*)`)
	reCreationDate := regexp.MustCompile(`created:\s+(.*)`)
	reExpiryDate := regexp.MustCompile(`paid-till:\s+(.*)`)
	reNameServer := regexp.MustCompile(`nserver:\s+(.*)`)
	reDomainStatus := regexp.MustCompile(`state:\s+(.*)`)
	reLastUpdateOfRDAPDB := regexp.MustCompile(`Last updated on (.*)`)

	// 解析注册商
	matchRegistrar := reRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = strings.TrimSpace(matchRegistrar[1])
	}

	// 解析创建日期
	matchCreationDate := reCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.CreationDate = matchCreationDate[1]
	}

	// 解析过期日期
	matchExpiryDate := reExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.RegistryExpiryDate = matchExpiryDate[1]
	}

	// 解析名称服务器
	matchNameServers := reNameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.NameServer = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.NameServer[i] = match[1]
		}
	}

	// 解析域名状态
	matchDomainStatuses := reDomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.DomainStatus = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.DomainStatus[i] = match[1]
		}
	}

	// 解析数据库更新时间
	matchLastUpdateOfRDAPDB := reLastUpdateOfRDAPDB.FindStringSubmatch(response)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		domainInfo.LastUpdateOfRDAPDB = matchLastUpdateOfRDAPDB[1]
	}

	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return structs.DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}

func ParseWhoisResponseSB(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// 使用正则表达式匹配 WHOIS 数据中的相关信息
	reCreationDate := regexp.MustCompile(`Creation Date: (.*)`)
	reExpiryDate := regexp.MustCompile(`Registry Expiry Date: (.*)`)
	reNameServer := regexp.MustCompile(`Name Server: (.*)`)
	reDNSSEC := regexp.MustCompile(`DNSSEC: (.*)`)
	reRegistrar := regexp.MustCompile(`Registrar: (.*)`)
	reDomainStatus := regexp.MustCompile(`Domain Status: (.*)`)
	reUpdatedDate := regexp.MustCompile(`Updated Date: (.*)`)
	reRegistrarIANAID := regexp.MustCompile(`Registrar IANA ID: (.*)`)
	reDNSSecDSData := regexp.MustCompile(`DNSSEC DS Data: (.*)`)
	reLastUpdateOfRDAPDB := regexp.MustCompile(`Last update of WHOIS database: (.*)`)

	// 解析创建日期
	matchCreationDate := reCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.CreationDate = matchCreationDate[1]
	}

	// 解析过期日期
	matchExpiryDate := reExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.RegistryExpiryDate = matchExpiryDate[1]
	}

	// 解析更新日期
	matchUpdatedDate := reUpdatedDate.FindStringSubmatch(response)
	if len(matchUpdatedDate) > 1 {
		domainInfo.UpdatedDate = matchUpdatedDate[1]
	}

	// 解析名称服务器
	matchNameServers := reNameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.NameServer = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.NameServer[i] = match[1]
		}
	}

	// 解析 DNSSEC
	matchDNSSEC := reDNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.DNSSec = matchDNSSEC[1]
	}

	// 解析注册商
	matchRegistrar := reRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = matchRegistrar[1]
	}

	// 解析域名状态
	matchDomainStatuses := reDomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.DomainStatus = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.DomainStatus[i] = match[1]
		}
	}

	// 解析 Registrar IANA ID
	matchRegistrarIANAID := reRegistrarIANAID.FindStringSubmatch(response)
	if len(matchRegistrarIANAID) > 1 {
		domainInfo.RegistrarIANAID = matchRegistrarIANAID[1]
	}

	// 解析 DNSSEC DS Data
	matchDNSSecDSData := reDNSSecDSData.FindStringSubmatch(response)
	if len(matchDNSSecDSData) > 1 {
		domainInfo.DNSSecDSData = []string{matchDNSSecDSData[1]}
	}

	// 解析数据库更新时间
	matchLastUpdateOfRDAPDB := reLastUpdateOfRDAPDB.FindStringSubmatch(response)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		domainInfo.LastUpdateOfRDAPDB = strings.TrimSuffix(matchLastUpdateOfRDAPDB[1], " \u003c\u003c\u003c")
	}

	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return structs.DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}
func ParseWhoisResponseMO(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// Use regular expressions to match relevant information in the WHOIS data
	reCreationDate := regexp.MustCompile(`Record created on (.*)`)
	reExpiryDate := regexp.MustCompile(`Record expires on (.*)`)
	reNameServer := regexp.MustCompile(`Domain name servers:\s*\n\s*-+\n((?:.+\n)+)`)

	// Parse creation date
	matchCreationDate := reCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.CreationDate = matchCreationDate[1]
	}

	// Parse expiry date
	matchExpiryDate := reExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.RegistryExpiryDate = matchExpiryDate[1]
	}

	// Parse name servers
	matchNameServers := reNameServer.FindStringSubmatch(response)
	if len(matchNameServers) > 1 {
		nameServers := strings.Split(strings.TrimSpace(matchNameServers[1]), "\n")
		domainInfo.NameServer = make([]string, len(nameServers))
		for i, ns := range nameServers {
			domainInfo.NameServer[i] = strings.TrimSpace(ns)
		}
	}

	// 设置数据库更新时间为数据处理时间
	now := time.Now().UTC().Format(time.RFC3339)
	domainInfo.LastUpdateOfRDAPDB = now

	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return structs.DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}

func ParseWhoisResponseAU(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// 清理响应数据
	cleanedResponse := strings.Replace(strings.TrimRight(response, "\r"), "\r", "", -1)

	// 使用正则表达式匹配 WHOIS 数据中的相关信息
	reRegistrar := regexp.MustCompile(`Registrar Name: (.*)`)
	reRegistrarIANAID := regexp.MustCompile(`Registrar IANA ID: (.*)`)
	reDomainStatus := regexp.MustCompile(`Status: (.*)`)
	reCreationDate := regexp.MustCompile(`Creation Date: (.*)`)
	reExpiryDate := regexp.MustCompile(`Registry Expiry Date: (.*)`)
	reUpdatedDate := regexp.MustCompile(`Last Modified: (.*)`)
	reNameServer := regexp.MustCompile(`Name Server: (.*)`)
	reDNSSEC := regexp.MustCompile(`DNSSEC: (.*)`)
	reDNSSecDSData := regexp.MustCompile(`DNSSEC DS Data: (.*)`)
	reLastUpdateOfRDAPDB := regexp.MustCompile(`Last update of WHOIS database: ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)`)

	// 解析创建日期
	matchCreationDate := reCreationDate.FindStringSubmatch(cleanedResponse)
	if len(matchCreationDate) > 1 {
		domainInfo.CreationDate = matchCreationDate[1]
	}

	// 解析过期日期
	matchExpiryDate := reExpiryDate.FindStringSubmatch(cleanedResponse)
	if len(matchExpiryDate) > 1 {
		domainInfo.RegistryExpiryDate = matchExpiryDate[1]
	}

	// 解析更新日期
	matchUpdatedDate := reUpdatedDate.FindStringSubmatch(cleanedResponse)
	if len(matchUpdatedDate) > 1 {
		domainInfo.UpdatedDate = matchUpdatedDate[1]
	}

	// 解析名称服务器
	matchNameServers := reNameServer.FindAllStringSubmatch(cleanedResponse, -1)
	if len(matchNameServers) > 0 {
		domainInfo.NameServer = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.NameServer[i] = match[1]
		}
	}

	// 解析 DNSSEC
	matchDNSSEC := reDNSSEC.FindStringSubmatch(cleanedResponse)
	if len(matchDNSSEC) > 1 {
		domainInfo.DNSSec = matchDNSSEC[1]
	}

	// 解析注册商
	matchRegistrar := reRegistrar.FindStringSubmatch(cleanedResponse)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = strings.TrimSpace(matchRegistrar[1])
	}

	// 解析域名状态
	matchDomainStatuses := reDomainStatus.FindAllStringSubmatch(cleanedResponse, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.DomainStatus = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.DomainStatus[i] = strings.TrimSpace(match[1])
		}
	}

	// 注册商 IANA ID 在给定示例中未提供，若需要解析请确保有正确格式的数据并使用相应正则表达式
	matchRegistrarIANAID := reRegistrarIANAID.FindStringSubmatch(cleanedResponse)
	if len(matchRegistrarIANAID) > 1 {
		domainInfo.RegistrarIANAID = matchRegistrarIANAID[1]
	}

	// 解析 DNSSEC DS Data
	matchDNSSecDSData := reDNSSecDSData.FindStringSubmatch(cleanedResponse)
	if len(matchDNSSecDSData) > 1 {
		domainInfo.DNSSecDSData = []string{matchDNSSecDSData[1]}
	}

	// 解析 Last update of WHOIS database
	matchLastUpdateOfRDAPDB := reLastUpdateOfRDAPDB.FindStringSubmatch(cleanedResponse)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		domainInfo.LastUpdateOfRDAPDB = matchLastUpdateOfRDAPDB[1]
	}

	if domainInfo.Registrar == "" {
		return structs.DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}

func ParseWhoisResponseSG(response string, domain string) (structs.DomainInfo, error) {
	// SG匹配有问题，有时间再修改了
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// 使用正则表达式匹配 WHOIS 数据中的相关信息
	reCreationDate := regexp.MustCompile(`Creation Date:\s+(.*)`)
	reExpiryDate := regexp.MustCompile(`Expiration Date:\s+(.*)`)
	reNameServer := regexp.MustCompile(`Name Servers?:\s+(.*)`)
	reDNSSEC := regexp.MustCompile(`DNSSEC:\s+(.*)`)
	reRegistrar := regexp.MustCompile(`Registrar:\s+(.*)`)
	reDomainStatus := regexp.MustCompile(`Domain Status:\s+(.*)`)
	reUpdatedDate := regexp.MustCompile(`Modified Date:\s+(.*)`)

	// 解析创建日期
	matchCreationDate := reCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.CreationDate = strings.TrimRight(matchCreationDate[1], "\r")
	}

	// 解析过期日期
	matchExpiryDate := reExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.RegistryExpiryDate = strings.TrimRight(matchExpiryDate[1], "\r")
	}

	// 解析更新日期
	matchUpdatedDate := reUpdatedDate.FindStringSubmatch(response)
	if len(matchUpdatedDate) > 1 {
		domainInfo.UpdatedDate = strings.TrimRight(matchUpdatedDate[1], "\r")
	}

	// 解析名称服务器
	matchNameServers := reNameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.NameServer = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.NameServer[i] = strings.TrimRight(match[1], "\r")
		}
	}

	// 解析 DNSSEC
	matchDNSSEC := reDNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.DNSSec = strings.TrimRight(matchDNSSEC[1], "\r\t")
	}

	// 解析注册商
	matchRegistrar := reRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = strings.TrimRight(matchRegistrar[1], "\r")
	}

	// 解析域名状态
	matchDomainStatuses := reDomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.DomainStatus = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.DomainStatus[i] = strings.TrimRight(match[1], "\r")
		}
	}

	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return structs.DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}

func ParseWhoisResponseLA(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// 使用正则表达式匹配 WHOIS 数据中的相关信息
	reRegistrar := regexp.MustCompile(`Registrar:\s+(.+)`)
	reRegistrarIANAID := regexp.MustCompile(`Registrar IANA ID:\s*(.*)$`)
	reDomainStatus := regexp.MustCompile(`Domain Status:\s+(.+)`)
	reCreationDate := regexp.MustCompile(`Creation Date:\s+(.+)`)
	reExpiryDate := regexp.MustCompile(`Registry Expiry Date:\s+(.+)`)
	reUpdatedDate := regexp.MustCompile(`Updated Date:\s+(.+)`)
	reNameServer := regexp.MustCompile(`Name Server:\s+(.+)`)
	reDNSSEC := regexp.MustCompile(`DNSSEC:\s+(.+)`)
	reLastUpdateOfRDAPDB := regexp.MustCompile(`>>> Last update of WHOIS database:\s+(.+)`)

	// 解析注册商
	matchRegistrar := reRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = strings.TrimSpace(matchRegistrar[1])
	}

	// 解析 Registrar IANA ID
	matchRegistrarIANAID := reRegistrarIANAID.FindStringSubmatch(response)
	if len(matchRegistrarIANAID) > 1 {
		ianaID := strings.TrimSpace(matchRegistrarIANAID[1])
		if ianaID != "" {
			domainInfo.RegistrarIANAID = ianaID
		}
	}

	// 解析域名状态
	matchDomainStatuses := reDomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.DomainStatus = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.DomainStatus[i] = strings.TrimSpace(match[1])
		}
	}

	// 解析创建日期
	matchCreationDate := reCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.CreationDate = strings.TrimSpace(matchCreationDate[1])
	}

	// 解析过期日期
	matchExpiryDate := reExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.RegistryExpiryDate = strings.TrimSpace(matchExpiryDate[1])
	}

	// 解析更新日期
	matchUpdatedDate := reUpdatedDate.FindStringSubmatch(response)
	if len(matchUpdatedDate) > 1 {
		domainInfo.UpdatedDate = strings.TrimSpace(matchUpdatedDate[1])
	}

	// 解析名称服务器
	matchNameServers := reNameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.NameServer = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.NameServer[i] = strings.TrimSpace(match[1])
		}
	}

	// 解析 DNSSEC
	matchDNSSEC := reDNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.DNSSec = strings.TrimSpace(matchDNSSEC[1])
	}

	// 解析数据库更新时间
	matchLastUpdateOfRDAPDB := reLastUpdateOfRDAPDB.FindStringSubmatch(response)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		// 去除末尾的 " <<<" 标记
		dbUpdate := strings.TrimSpace(matchLastUpdateOfRDAPDB[1])
		domainInfo.LastUpdateOfRDAPDB = strings.TrimSuffix(dbUpdate, " <<<")
	}

	// 验证必要字段
	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return structs.DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}

// ParseWhoisResponseJP parses WHOIS response for .jp domains (including .co.jp and other variants)
func ParseWhoisResponseJP(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// 解析域名 - 尝试两种格式
	domainInfo.DomainName = matchFirstGroup(reJPDomainName, response,
		func() string { return matchFirstGroup(reJPDomainNameAlt, response, nil) })
	if domainInfo.DomainName == "" {
		domainInfo.DomainName = domain
	}

	// 解析注册人/组织 - 尝试两种格式
	domainInfo.Registrar = matchFirstGroup(reJPRegistrant, response,
		func() string { return matchFirstGroup(reJPOrganization, response, nil) })

	// 解析名称服务器 - 尝试两种格式
	domainInfo.NameServer = matchAllFirstGroup(reJPNameServer, response)
	if len(domainInfo.NameServer) == 0 {
		domainInfo.NameServer = matchAllFirstGroup(reJPNameServerAlt, response)
	}

	// 解析 DNSSEC - 支持 [Signing Key] 和 s. [署名鍵] 两种格式
	domainInfo.DNSSec = "unsigned"
	if signingKeyRaw := extractSigningKey(response); signingKeyRaw != "" {
		domainInfo.DNSSec = "signedDelegation"
		domainInfo.DNSSecDSData = []string{signingKeyRaw}
	}

	// 解析注册日期 (格式: 2001/05/23)
	if dateStr := matchFirstGroup(reJPCreationDate, response, nil); dateStr != "" {
		if t, err := time.Parse("2006/01/02", dateStr); err == nil {
			domainInfo.CreationDate = t.Format("2006-01-02")
		}
	}

	// 解析过期日期 - 优先 [有効期限] 字段，再从 [状態] 中提取
	if dateStr := matchFirstGroup(reJPExpiryDate, response, nil); dateStr != "" {
		if t, err := time.Parse("2006/01/02", dateStr); err == nil {
			domainInfo.RegistryExpiryDate = t.Format("2006-01-02")
		}
	}

	// 解析 [状態] - 同时提取过期日期(如有)和状态文本
	var statuses []string
	if statusStr := matchFirstGroup(reJPStatus, response, nil); statusStr != "" {
		// 从状态中提取过期日期 (适用于 co.jp: "Connected (2026/10/31)")
		if domainInfo.RegistryExpiryDate == "" {
			if matchExpiry := reJPExpiryInStatus.FindStringSubmatch(statusStr); len(matchExpiry) > 1 {
				if t, err := time.Parse("2006/01/02", matchExpiry[1]); err == nil {
					domainInfo.RegistryExpiryDate = t.Format("2006-01-02")
				}
			}
		}
		// 清理状态文本（移除日期部分）
		statusClean := strings.TrimSpace(reJPExpiryInStatus.ReplaceAllString(statusStr, ""))
		if statusClean != "" {
			statuses = append(statuses, statusClean)
		}
	}

	// 解析锁定状态
	for _, match := range reJPLockStatus.FindAllStringSubmatch(response, -1) {
		if len(match) > 1 {
			statuses = append(statuses, strings.TrimSpace(match[1]))
		}
	}
	if len(statuses) > 0 {
		domainInfo.DomainStatus = statuses
	}

	// 解析最终更新时间 (格式: 2025/06/01 01:05:04 (JST))
	if dateStr := matchFirstGroup(reJPUpdatedDate, response, nil); dateStr != "" {
		dateStr = reJPTimezone.ReplaceAllString(dateStr, "")
		if t, err := time.Parse("2006/01/02 15:04:05", dateStr); err == nil {
			domainInfo.UpdatedDate = t.Add(-9 * time.Hour).Format(time.RFC3339)
		}
	}

	// 设置数据库更新时间为当前时间
	domainInfo.LastUpdateOfRDAPDB = time.Now().UTC().Format(time.RFC3339)

	// 验证必要字段
	if domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return structs.DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}

// matchFirstGroup 返回正则第一个捕获组的 TrimSpace 结果，未匹配时调用 fallback
func matchFirstGroup(re *regexp.Regexp, s string, fallback func() string) string {
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		if v := strings.TrimSpace(m[1]); v != "" {
			return v
		}
	}
	if fallback != nil {
		return fallback()
	}
	return ""
}

// matchAllFirstGroup 返回正则所有匹配的第一个捕获组
func matchAllFirstGroup(re *regexp.Regexp, s string) []string {
	matches := re.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return nil
	}
	var results []string
	for _, m := range matches {
		if v := strings.TrimSpace(m[1]); v != "" {
			results = append(results, v)
		}
	}
	return results
}

// extractSigningKey 从 JP WHOIS 响应中提取 DNSSEC 签名数据
func extractSigningKey(response string) string {
	// 支持 [Signing Key] 和 s. [署名鍵] 两种标签
	var afterKey string
	if idx := strings.Index(response, "[Signing Key]"); idx != -1 {
		afterKey = response[idx+len("[Signing Key]"):]
	} else if idx := strings.Index(response, "s. [署名鍵]"); idx != -1 {
		afterKey = response[idx+len("s. [署名鍵]"):]
	} else {
		return ""
	}

	// 找到下一个字段或空行作为结束边界
	endIdx := len(afterKey)
	if i := strings.Index(afterKey, "\n\n"); i != -1 {
		endIdx = i
	}
	if i := strings.Index(afterKey, "\n["); i != -1 && i < endIdx {
		endIdx = i
	}

	// 清理格式：移除括号、换行，压缩空格
	raw := afterKey[:endIdx]
	raw = strings.NewReplacer("(", "", ")", "", "\n", " ", "\t", " ").Replace(raw)
	return strings.TrimSpace(reMultiSpace.ReplaceAllString(raw, " "))
}
