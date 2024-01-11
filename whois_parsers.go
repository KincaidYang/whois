package main

import (
	"regexp"
	"strings"
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
		domainInfo.CreationDate = matchCreationDate[1]
	}

	// 解析过期日期
	matchExpiryDate := reExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.RegistryExpiryDate = matchExpiryDate[1]
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
		domainInfo.DNSSec = matchDNSSEC[1]
	}

	// 解析注册商
	matchRegistrar := reRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = matchRegistrar[1]
	}

	// 解析域名状态
	matchDomainStatus := reDomainStatus.FindStringSubmatch(response)
	if len(matchDomainStatus) > 1 {
		domainInfo.DomainStatus = []string{matchDomainStatus[1]}
	}

	return domainInfo, nil
}

func parseWhoisResponseTW(response string, domain string) (DomainInfo, error) {
	var domainInfo DomainInfo
	domainInfo.DomainName = domain

	// 使用正则表达式匹配 WHOIS 数据中的相关信息
	reCreationDate := regexp.MustCompile(`Record created on ([0-9]{4}-[0-9]{2}-[0-9]{2})`)
	reExpiryDate := regexp.MustCompile(`Record expires on ([0-9]{4}-[0-9]{2}-[0-9]{2})`)
	reNameServer := regexp.MustCompile(`(?s)Domain servers in listed order:\n\s+(.*?)\n\n`)
	reRegistrar := regexp.MustCompile(`Registration Service Provider: (.*)`)
	reDomainStatus := regexp.MustCompile(`Domain Status: (.*)`)

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

	// 解析名称服务器
	matchNameServers := reNameServer.FindStringSubmatch(response)
	if len(matchNameServers) > 1 {
		servers := strings.Split(strings.TrimSpace(matchNameServers[1]), "\n")
		domainInfo.NameServer = make([]string, len(servers))
		for i, server := range servers {
			domainInfo.NameServer[i] = strings.TrimSpace(server)
		}
	}

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

	return domainInfo, nil
}
func parseWhoisResponseSO(response string, domain string) (DomainInfo, error) {
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

	return domainInfo, nil
}
func parseWhoisResponseSG(response string, domain string) (DomainInfo, error) {
	// SG匹配有问题，有时间再修改了
	var domainInfo DomainInfo
	domainInfo.DomainName = domain

	// 使用正则表达式匹配 WHOIS 数据中的相关信息
	reCreationDate := regexp.MustCompile(`Creation Date:\s+(.*)`)
	reExpiryDate := regexp.MustCompile(`Expiration Date:\s+(.*)`)
	reNameServer := regexp.MustCompile(`Name Servers?:\s+(?s)(.*)`)
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

	return domainInfo, nil
}
func parseWhoisResponseRU(response string, domain string) (DomainInfo, error) {
	var domainInfo DomainInfo
	domainInfo.DomainName = domain

	// 使用正则表达式匹配 WHOIS 数据中的相关信息
	reCreationDate := regexp.MustCompile(`created:\s+(.*)`)
	reExpiryDate := regexp.MustCompile(`paid-till:\s+(.*)`)
	reNameServer := regexp.MustCompile(`nserver:\s+(.*)`)
	reDomainStatus := regexp.MustCompile(`state:\s+(.*)`)

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

	return domainInfo, nil
}
