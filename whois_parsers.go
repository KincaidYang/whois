package main

import (
	"regexp"
)

func parseWhoisResponseCN(response string, domain string) (DomainInfo, error) {
	var domainInfo DomainInfo
	domainInfo.DomainName = domain

	// 使用正则表达式匹配 WHOIS 数据中的相关信息
	reCreationDate := regexp.MustCompile(`Registration Time: (.*)`)
	reExpiryDate := regexp.MustCompile(`Expiration Time: (.*)`)
	reNameServer1 := regexp.MustCompile(`Name Server: (.*)`)
	reNameServer2 := regexp.MustCompile(`Name Server: .*[\r\n]+(.*)`)

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
	matchNameServer1 := reNameServer1.FindStringSubmatch(response)
	matchNameServer2 := reNameServer2.FindStringSubmatch(response)
	if len(matchNameServer1) > 1 && len(matchNameServer2) > 1 {
		domainInfo.NameServer = []string{matchNameServer1[1], matchNameServer2[1]}
	}

	// ...您可以根据需要解析其他信息，例如注册商、域名状态等...

	return domainInfo, nil
}
