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

	// ...您可以根据需要解析其他信息...

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

	// ...您可以根据需要解析其他信息...

	return domainInfo, nil
}
func parseWhoisResponseCO(response string, domain string) (DomainInfo, error) {
	var domainInfo DomainInfo
	domainInfo.DomainName = domain

	// 使用正则表达式匹配 WHOIS 数据中的相关信息
	reCreationDate := regexp.MustCompile(`Creation Date: (.*)`)
	reExpiryDate := regexp.MustCompile(`Registry Expiry Date: (.*)`)
	reUpdatedDate := regexp.MustCompile(`Updated Date: (.*)`)
	reNameServer := regexp.MustCompile(`Name Server: (.*)`)
	reDNSSEC := regexp.MustCompile(`DNSSEC: (.*)`)
	reRegistrar := regexp.MustCompile(`Registrar: (.*)`)
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

	// ...您可以根据需要解析其他信息...

	return domainInfo, nil
}
