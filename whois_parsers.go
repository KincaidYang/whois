package main

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

func parseWhoisResponseCN(response string, domain string) (DomainInfo, error) {
	var domainInfo DomainInfo
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
			return DomainInfo{}, err
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
			return DomainInfo{}, err
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
		return DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}
func parseWhoisResponseHK(response string, domain string) (DomainInfo, error) {
	var domainInfo DomainInfo
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
		return DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}

func parseWhoisResponseTW(response string, domain string) (DomainInfo, error) {
	var domainInfo DomainInfo
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
			return DomainInfo{}, err
		}
		// 将时间转换为 UTC，并格式化为新的字符串
		domainInfo.CreationDate = t.Add(-8 * time.Hour).Format(time.RFC3339Nano)
	}

	// 解析过期日期
	matchExpiryDate := reExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		t, err := time.Parse("2006-01-02 15:04:05", matchExpiryDate[1])
		if err != nil {
			return DomainInfo{}, err
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
		return DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}
func parseWhoisResponseSO(response string, domain string) (DomainInfo, error) {
	var domainInfo DomainInfo
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
		domainInfo.DNSSecDSData = matchDNSSecDSData[1]
	}

	// 解析数据库更新时间
	matchLastUpdateOfRDAPDB := reLastUpdateOfRDAPDB.FindStringSubmatch(response)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		domainInfo.LastUpdateOfRDAPDB = strings.TrimSuffix(matchLastUpdateOfRDAPDB[1], " \u003c\u003c\u003c")
	}

	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}
func parseWhoisResponseRU(response string, domain string) (DomainInfo, error) {
	var domainInfo DomainInfo
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
		return DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}

func parseWhoisResponseSB(response string, domain string) (DomainInfo, error) {
	var domainInfo DomainInfo
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
		domainInfo.DNSSecDSData = matchDNSSecDSData[1]
	}

	// 解析数据库更新时间
	matchLastUpdateOfRDAPDB := reLastUpdateOfRDAPDB.FindStringSubmatch(response)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		domainInfo.LastUpdateOfRDAPDB = strings.TrimSuffix(matchLastUpdateOfRDAPDB[1], " \u003c\u003c\u003c")
	}

	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}
func parseWhoisResponseMO(response string, domain string) (DomainInfo, error) {
	var domainInfo DomainInfo
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
		return DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}

func parseWhoisResponseAU(response string, domain string) (DomainInfo, error) {
	var domainInfo DomainInfo
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
		domainInfo.DNSSecDSData = matchDNSSecDSData[1]
	}

	// 解析 Last update of WHOIS database
	matchLastUpdateOfRDAPDB := reLastUpdateOfRDAPDB.FindStringSubmatch(cleanedResponse)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		domainInfo.LastUpdateOfRDAPDB = matchLastUpdateOfRDAPDB[1]
	}

	if domainInfo.Registrar == "" {
		return DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}

func parseWhoisResponseSG(response string, domain string) (DomainInfo, error) {
	// SG匹配有问题，有时间再修改了
	var domainInfo DomainInfo
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
		return DomainInfo{}, errors.New("domain not found")
	}

	return domainInfo, nil
}
