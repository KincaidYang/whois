package whois_tools

import (
	"regexp"
	"strings"
	"time"

	"github.com/KincaidYang/whois/rdap_tools/structs"
	"github.com/KincaidYang/whois/utils"
)

// 预编译正则表达式（所有解析器共享，避免每次调用重复编译）
var (
	// CN / xn--fiqs8s / xn--fiqz9s
	reCNCreationDate  = regexp.MustCompile(`Registration Time: (.*)`)
	reCNExpiryDate    = regexp.MustCompile(`Expiration Time: (.*)`)
	reCNNameServer    = regexp.MustCompile(`Name Server: (.*)`)
	reCNDNSSEC        = regexp.MustCompile(`DNSSEC: (.*)`)
	reCNRegistrar     = regexp.MustCompile(`Sponsoring Registrar: (.*)`)
	reCNDomainStatus  = regexp.MustCompile(`Domain Status: (.*)`)

	// HK / xn--j6w193g
	reHKCreationDate  = regexp.MustCompile(`Domain Name Commencement Date: (.*)`)
	reHKExpiryDate    = regexp.MustCompile(`Expiry Date: (.*)`)
	reHKNameServer    = regexp.MustCompile(`Name Servers Information:\s*\n\n((?:.+\n)+)`)
	reHKDNSSEC        = regexp.MustCompile(`DNSSEC: (.*)`)
	reHKRegistrar     = regexp.MustCompile(`Registrar Name: (.*)`)
	reHKDomainStatus  = regexp.MustCompile(`Domain Status: (.*)`)

	// TW
	reTWRegistrar    = regexp.MustCompile(`Registration Service Provider: (.*)`)
	reTWDomainStatus = regexp.MustCompile(`Domain Status: (.*)`)
	reTWCreationDate = regexp.MustCompile(`Record created on ([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})`)
	reTWExpiryDate   = regexp.MustCompile(`Record expires on ([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})`)
	reTWNameServer   = regexp.MustCompile(`(?s)Domain servers in listed order:\n\s+(.*?)\n\n`)
	reTWDNSSEC       = regexp.MustCompile(`DNSSEC: (.*)`)

	// SO
	reSORegistrar          = regexp.MustCompile(`Registrar: (.*)`)
	reSODomainStatus       = regexp.MustCompile(`Domain Status: (.*)`)
	reSOUpdatedDate        = regexp.MustCompile(`Updated Date: (.*)`)
	reSORegistrarIANAID    = regexp.MustCompile(`Registrar IANA ID: (.*)`)
	reSOCreationDate       = regexp.MustCompile(`Creation Date: (.*)`)
	reSOExpiryDate         = regexp.MustCompile(`Registry Expiry Date: (.*)`)
	reSONameServer         = regexp.MustCompile(`Name Server: (.*)`)
	reSODNSSEC             = regexp.MustCompile(`DNSSEC: (.*)`)
	reSODNSSecDSData       = regexp.MustCompile(`DNSSEC DS Data: (.*)`)
	reSOLastUpdateOfRDAPDB = regexp.MustCompile(`Last update of WHOIS database: (.*)`)

	// RU / SU
	reRURegistrar          = regexp.MustCompile(`registrar: (.*)`)
	reRUCreationDate       = regexp.MustCompile(`created:\s+(.*)`)
	reRUExpiryDate         = regexp.MustCompile(`paid-till:\s+(.*)`)
	reRUNameServer         = regexp.MustCompile(`nserver:\s+(.*)`)
	reRUDomainStatus       = regexp.MustCompile(`state:\s+(.*)`)
	reRULastUpdateOfRDAPDB = regexp.MustCompile(`Last updated on (.*)`)

	// SB
	reSBCreationDate       = regexp.MustCompile(`Creation Date: (.*)`)
	reSBExpiryDate         = regexp.MustCompile(`Registry Expiry Date: (.*)`)
	reSBNameServer         = regexp.MustCompile(`Name Server: (.*)`)
	reSBDNSSEC             = regexp.MustCompile(`DNSSEC: (.*)`)
	reSBRegistrar          = regexp.MustCompile(`Registrar: (.*)`)
	reSBDomainStatus       = regexp.MustCompile(`Domain Status: (.*)`)
	reSBUpdatedDate        = regexp.MustCompile(`Updated Date: (.*)`)
	reSBRegistrarIANAID    = regexp.MustCompile(`Registrar IANA ID: (.*)`)
	reSBDNSSecDSData       = regexp.MustCompile(`DNSSEC DS Data: (.*)`)
	reSBLastUpdateOfRDAPDB = regexp.MustCompile(`Last update of WHOIS database: (.*)`)

	// MO
	reMOCreationDate = regexp.MustCompile(`Record created on (.*)`)
	reMOExpiryDate   = regexp.MustCompile(`Record expires on (.*)`)
	reMONameServer   = regexp.MustCompile(`Domain name servers:\s*\n\s*-+\n((?:.+\n)+)`)

	// AU
	reAURegistrar          = regexp.MustCompile(`Registrar Name: (.*)`)
	reAURegistrarIANAID    = regexp.MustCompile(`Registrar IANA ID: (.*)`)
	reAUDomainStatus       = regexp.MustCompile(`Status: (.*)`)
	reAUCreationDate       = regexp.MustCompile(`Creation Date: (.*)`)
	reAUExpiryDate         = regexp.MustCompile(`Registry Expiry Date: (.*)`)
	reAUUpdatedDate        = regexp.MustCompile(`Last Modified: (.*)`)
	reAUNameServer         = regexp.MustCompile(`Name Server: (.*)`)
	reAUDNSSEC             = regexp.MustCompile(`DNSSEC: (.*)`)
	reAUDNSSecDSData       = regexp.MustCompile(`DNSSEC DS Data: (.*)`)
	reAULastUpdateOfRDAPDB = regexp.MustCompile(`Last update of WHOIS database: ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)`)

	// SG
	reSGCreationDate  = regexp.MustCompile(`Creation Date:\s+(.*)`)
	reSGExpiryDate    = regexp.MustCompile(`Expiration Date:\s+(.*)`)
	reSGNameServer    = regexp.MustCompile(`Name Servers?:\s+(.*)`)
	reSGDNSSEC        = regexp.MustCompile(`DNSSEC:\s+(.*)`)
	reSGRegistrar     = regexp.MustCompile(`Registrar:\s+(.*)`)
	reSGDomainStatus  = regexp.MustCompile(`Domain Status:\s+(.*)`)
	reSGUpdatedDate   = regexp.MustCompile(`Modified Date:\s+(.*)`)

	// LA
	reLARegistrar          = regexp.MustCompile(`Registrar:\s+(.+)`)
	reLARegistrarIANAID    = regexp.MustCompile(`Registrar IANA ID:\s*(.*)$`)
	reLADomainStatus       = regexp.MustCompile(`Domain Status:\s+(.+)`)
	reLACreationDate       = regexp.MustCompile(`Creation Date:\s+(.+)`)
	reLAExpiryDate         = regexp.MustCompile(`Registry Expiry Date:\s+(.+)`)
	reLAUpdatedDate        = regexp.MustCompile(`Updated Date:\s+(.+)`)
	reLANameServer         = regexp.MustCompile(`Name Server:\s+(.+)`)
	reLADNSSEC             = regexp.MustCompile(`DNSSEC:\s+(.+)`)
	reLALastUpdateOfRDAPDB = regexp.MustCompile(`>>> Last update of WHOIS database:\s+(.+)`)

	// JP WHOIS 预编译正则表达式
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

	// 解析创建日期
	matchCreationDate := reCNCreationDate.FindStringSubmatch(response)
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
	matchExpiryDate := reCNExpiryDate.FindStringSubmatch(response)
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
	matchNameServers := reCNNameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.NameServer = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.NameServer[i] = match[1]
		}
	}

	// 解析 DNSSEC
	matchDNSSEC := reCNDNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.DNSSec = matchDNSSEC[1]
	}

	// 解析注册商
	matchRegistrar := reCNRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = matchRegistrar[1]
	}

	// 解析域名状态
	matchDomainStatuses := reCNDomainStatus.FindAllStringSubmatch(response, -1)
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
		return structs.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}
func ParseWhoisResponseHK(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// 解析创建日期
	matchCreationDate := reHKCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		CreationDate := strings.TrimSpace(matchCreationDate[1])
		parsedDate, err := time.Parse("02-01-2006", CreationDate)
		if err == nil {
			domainInfo.CreationDate = parsedDate.Format("2006-01-02")
		}
	}

	// 解析过期日期
	matchExpiryDate := reHKExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		expiryDate := strings.TrimSpace(matchExpiryDate[1])
		parsedDate, err := time.Parse("02-01-2006", expiryDate)
		if err == nil {
			domainInfo.RegistryExpiryDate = parsedDate.Format("2006-01-02")
		}
	}

	// 解析名称服务器
	matchNameServers := reHKNameServer.FindStringSubmatch(response)
	if len(matchNameServers) > 1 {
		nameServers := strings.Split(strings.TrimSpace(matchNameServers[1]), "\n")
		domainInfo.NameServer = make([]string, len(nameServers))
		for i, ns := range nameServers {
			domainInfo.NameServer[i] = strings.TrimSpace(ns)
		}
	}

	// 解析 DNSSEC
	matchDNSSEC := reHKDNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.DNSSec = strings.TrimSpace(matchDNSSEC[1])
	}

	// 解析注册商
	matchRegistrar := reHKRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = matchRegistrar[1]
	}

	// 解析域名状态
	matchDomainStatus := reHKDomainStatus.FindStringSubmatch(response)
	if len(matchDomainStatus) > 1 {
		domainInfo.DomainStatus = []string{strings.TrimSpace(matchDomainStatus[1])}
	}

	// 设置数据库更新时间为数据处理时间
	now := time.Now().UTC().Format(time.RFC3339)
	domainInfo.LastUpdateOfRDAPDB = now

	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return structs.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}

func ParseWhoisResponseTW(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// 解析注册商
	matchRegistrar := reTWRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = strings.TrimSpace(matchRegistrar[1])
	}

	// 解析域名状态
	matchDomainStatuses := reTWDomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.DomainStatus = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.DomainStatus[i] = strings.TrimSpace(match[1])
		}
	}

	// 解析创建日期
	matchCreationDate := reTWCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		t, err := time.Parse("2006-01-02 15:04:05", matchCreationDate[1])
		if err != nil {
			return structs.DomainInfo{}, err
		}
		// 将时间转换为 UTC，并格式化为新的字符串
		domainInfo.CreationDate = t.Add(-8 * time.Hour).Format(time.RFC3339Nano)
	}

	// 解析过期日期
	matchExpiryDate := reTWExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		t, err := time.Parse("2006-01-02 15:04:05", matchExpiryDate[1])
		if err != nil {
			return structs.DomainInfo{}, err
		}
		// 将时间转换为 UTC，并格式化为新的字符串
		domainInfo.RegistryExpiryDate = t.Add(-8 * time.Hour).Format(time.RFC3339Nano)
	}

	// 解析名称服务器
	matchNameServers := reTWNameServer.FindStringSubmatch(response)
	if len(matchNameServers) > 1 {
		servers := strings.Split(strings.TrimSpace(matchNameServers[1]), "\n")
		domainInfo.NameServer = make([]string, len(servers))
		for i, server := range servers {
			domainInfo.NameServer[i] = strings.TrimSpace(server)
		}
	}

	// 解析 DNSSEC
	matchDNSSEC := reTWDNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.DNSSec = matchDNSSEC[1]
	}

	// 设置数据库更新时间为数据处理时间
	now := time.Now().UTC().Format(time.RFC3339)
	domainInfo.LastUpdateOfRDAPDB = now

	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return structs.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}
func ParseWhoisResponseSO(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// 解析注册商
	matchRegistrar := reSORegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = matchRegistrar[1]
	}

	// 解析域名状态
	matchDomainStatuses := reSODomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.DomainStatus = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.DomainStatus[i] = match[1]
		}
	}

	// 解析 Registrar IANA ID
	matchRegistrarIANAID := reSORegistrarIANAID.FindStringSubmatch(response)
	if len(matchRegistrarIANAID) > 1 {
		domainInfo.RegistrarIANAID = matchRegistrarIANAID[1]
	}

	// 解析创建日期
	matchCreationDate := reSOCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.CreationDate = matchCreationDate[1]
	}

	// 解析过期日期
	matchExpiryDate := reSOExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.RegistryExpiryDate = matchExpiryDate[1]
	}

	// 解析更新日期
	matchUpdatedDate := reSOUpdatedDate.FindStringSubmatch(response)
	if len(matchUpdatedDate) > 1 {
		domainInfo.UpdatedDate = matchUpdatedDate[1]
	}

	// 解析名称服务器
	matchNameServers := reSONameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.NameServer = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.NameServer[i] = match[1]
		}
	}

	// 解析 DNSSEC
	matchDNSSEC := reSODNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.DNSSec = matchDNSSEC[1]
	}

	// 解析 DNSSEC DS Data
	matchDNSSecDSData := reSODNSSecDSData.FindStringSubmatch(response)
	if len(matchDNSSecDSData) > 1 {
		domainInfo.DNSSecDSData = []string{matchDNSSecDSData[1]}
	}

	// 解析数据库更新时间
	matchLastUpdateOfRDAPDB := reSOLastUpdateOfRDAPDB.FindStringSubmatch(response)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		domainInfo.LastUpdateOfRDAPDB = strings.TrimSuffix(matchLastUpdateOfRDAPDB[1], " \u003c\u003c\u003c")
	}

	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return structs.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}
func ParseWhoisResponseRU(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// 解析注册商
	matchRegistrar := reRURegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = strings.TrimSpace(matchRegistrar[1])
	}

	// 解析创建日期
	matchCreationDate := reRUCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.CreationDate = matchCreationDate[1]
	}

	// 解析过期日期
	matchExpiryDate := reRUExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.RegistryExpiryDate = matchExpiryDate[1]
	}

	// 解析名称服务器
	matchNameServers := reRUNameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.NameServer = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.NameServer[i] = match[1]
		}
	}

	// 解析域名状态
	matchDomainStatuses := reRUDomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.DomainStatus = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.DomainStatus[i] = match[1]
		}
	}

	// 解析数据库更新时间
	matchLastUpdateOfRDAPDB := reRULastUpdateOfRDAPDB.FindStringSubmatch(response)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		domainInfo.LastUpdateOfRDAPDB = matchLastUpdateOfRDAPDB[1]
	}

	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return structs.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}

func ParseWhoisResponseSB(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain


	// 解析创建日期
	matchCreationDate := reSBCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.CreationDate = matchCreationDate[1]
	}

	// 解析过期日期
	matchExpiryDate := reSBExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.RegistryExpiryDate = matchExpiryDate[1]
	}

	// 解析更新日期
	matchUpdatedDate := reSBUpdatedDate.FindStringSubmatch(response)
	if len(matchUpdatedDate) > 1 {
		domainInfo.UpdatedDate = matchUpdatedDate[1]
	}

	// 解析名称服务器
	matchNameServers := reSBNameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.NameServer = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.NameServer[i] = match[1]
		}
	}

	// 解析 DNSSEC
	matchDNSSEC := reSBDNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.DNSSec = matchDNSSEC[1]
	}

	// 解析注册商
	matchRegistrar := reSBRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = matchRegistrar[1]
	}

	// 解析域名状态
	matchDomainStatuses := reSBDomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.DomainStatus = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.DomainStatus[i] = match[1]
		}
	}

	// 解析 Registrar IANA ID
	matchRegistrarIANAID := reSBRegistrarIANAID.FindStringSubmatch(response)
	if len(matchRegistrarIANAID) > 1 {
		domainInfo.RegistrarIANAID = matchRegistrarIANAID[1]
	}

	// 解析 DNSSEC DS Data
	matchDNSSecDSData := reSBDNSSecDSData.FindStringSubmatch(response)
	if len(matchDNSSecDSData) > 1 {
		domainInfo.DNSSecDSData = []string{matchDNSSecDSData[1]}
	}

	// 解析数据库更新时间
	matchLastUpdateOfRDAPDB := reSBLastUpdateOfRDAPDB.FindStringSubmatch(response)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		domainInfo.LastUpdateOfRDAPDB = strings.TrimSuffix(matchLastUpdateOfRDAPDB[1], " \u003c\u003c\u003c")
	}

	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return structs.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}
func ParseWhoisResponseMO(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// Parse creation date
	matchCreationDate := reMOCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.CreationDate = matchCreationDate[1]
	}

	// Parse expiry date
	matchExpiryDate := reMOExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.RegistryExpiryDate = matchExpiryDate[1]
	}

	// Parse name servers
	matchNameServers := reMONameServer.FindStringSubmatch(response)
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
		return structs.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}

func ParseWhoisResponseAU(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// 清理响应数据
	cleanedResponse := strings.Replace(strings.TrimRight(response, "\r"), "\r", "", -1)

	// 解析创建日期
	matchCreationDate := reAUCreationDate.FindStringSubmatch(cleanedResponse)
	if len(matchCreationDate) > 1 {
		domainInfo.CreationDate = matchCreationDate[1]
	}

	// 解析过期日期
	matchExpiryDate := reAUExpiryDate.FindStringSubmatch(cleanedResponse)
	if len(matchExpiryDate) > 1 {
		domainInfo.RegistryExpiryDate = matchExpiryDate[1]
	}

	// 解析更新日期
	matchUpdatedDate := reAUUpdatedDate.FindStringSubmatch(cleanedResponse)
	if len(matchUpdatedDate) > 1 {
		domainInfo.UpdatedDate = matchUpdatedDate[1]
	}

	// 解析名称服务器
	matchNameServers := reAUNameServer.FindAllStringSubmatch(cleanedResponse, -1)
	if len(matchNameServers) > 0 {
		domainInfo.NameServer = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.NameServer[i] = match[1]
		}
	}

	// 解析 DNSSEC
	matchDNSSEC := reAUDNSSEC.FindStringSubmatch(cleanedResponse)
	if len(matchDNSSEC) > 1 {
		domainInfo.DNSSec = matchDNSSEC[1]
	}

	// 解析注册商
	matchRegistrar := reAURegistrar.FindStringSubmatch(cleanedResponse)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = strings.TrimSpace(matchRegistrar[1])
	}

	// 解析域名状态
	matchDomainStatuses := reAUDomainStatus.FindAllStringSubmatch(cleanedResponse, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.DomainStatus = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.DomainStatus[i] = strings.TrimSpace(match[1])
		}
	}

	// 注册商 IANA ID 在给定示例中未提供，若需要解析请确保有正确格式的数据并使用相应正则表达式
	matchRegistrarIANAID := reAURegistrarIANAID.FindStringSubmatch(cleanedResponse)
	if len(matchRegistrarIANAID) > 1 {
		domainInfo.RegistrarIANAID = matchRegistrarIANAID[1]
	}

	// 解析 DNSSEC DS Data
	matchDNSSecDSData := reAUDNSSecDSData.FindStringSubmatch(cleanedResponse)
	if len(matchDNSSecDSData) > 1 {
		domainInfo.DNSSecDSData = []string{matchDNSSecDSData[1]}
	}

	// 解析 Last update of WHOIS database
	matchLastUpdateOfRDAPDB := reAULastUpdateOfRDAPDB.FindStringSubmatch(cleanedResponse)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		domainInfo.LastUpdateOfRDAPDB = matchLastUpdateOfRDAPDB[1]
	}

	if domainInfo.Registrar == "" {
		return structs.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}

func ParseWhoisResponseSG(response string, domain string) (structs.DomainInfo, error) {
	// SG匹配有问题，有时间再修改了
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// 解析创建日期
	matchCreationDate := reSGCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.CreationDate = strings.TrimRight(matchCreationDate[1], "\r")
	}

	// 解析过期日期
	matchExpiryDate := reSGExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.RegistryExpiryDate = strings.TrimRight(matchExpiryDate[1], "\r")
	}

	// 解析更新日期
	matchUpdatedDate := reSGUpdatedDate.FindStringSubmatch(response)
	if len(matchUpdatedDate) > 1 {
		domainInfo.UpdatedDate = strings.TrimRight(matchUpdatedDate[1], "\r")
	}

	// 解析名称服务器
	matchNameServers := reSGNameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.NameServer = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.NameServer[i] = strings.TrimRight(match[1], "\r")
		}
	}

	// 解析 DNSSEC
	matchDNSSEC := reSGDNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.DNSSec = strings.TrimRight(matchDNSSEC[1], "\r\t")
	}

	// 解析注册商
	matchRegistrar := reSGRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = strings.TrimRight(matchRegistrar[1], "\r")
	}

	// 解析域名状态
	matchDomainStatuses := reSGDomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.DomainStatus = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.DomainStatus[i] = strings.TrimRight(match[1], "\r")
		}
	}

	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return structs.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}

func ParseWhoisResponseLA(response string, domain string) (structs.DomainInfo, error) {
	var domainInfo structs.DomainInfo
	domainInfo.DomainName = domain

	// 解析注册商
	matchRegistrar := reLARegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = strings.TrimSpace(matchRegistrar[1])
	}

	// 解析 Registrar IANA ID
	matchRegistrarIANAID := reLARegistrarIANAID.FindStringSubmatch(response)
	if len(matchRegistrarIANAID) > 1 {
		ianaID := strings.TrimSpace(matchRegistrarIANAID[1])
		if ianaID != "" {
			domainInfo.RegistrarIANAID = ianaID
		}
	}

	// 解析域名状态
	matchDomainStatuses := reLADomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.DomainStatus = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.DomainStatus[i] = strings.TrimSpace(match[1])
		}
	}

	// 解析创建日期
	matchCreationDate := reLACreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.CreationDate = strings.TrimSpace(matchCreationDate[1])
	}

	// 解析过期日期
	matchExpiryDate := reLAExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.RegistryExpiryDate = strings.TrimSpace(matchExpiryDate[1])
	}

	// 解析更新日期
	matchUpdatedDate := reLAUpdatedDate.FindStringSubmatch(response)
	if len(matchUpdatedDate) > 1 {
		domainInfo.UpdatedDate = strings.TrimSpace(matchUpdatedDate[1])
	}

	// 解析名称服务器
	matchNameServers := reLANameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.NameServer = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.NameServer[i] = strings.TrimSpace(match[1])
		}
	}

	// 解析 DNSSEC
	matchDNSSEC := reLADNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.DNSSec = strings.TrimSpace(matchDNSSEC[1])
	}

	// 解析数据库更新时间
	matchLastUpdateOfRDAPDB := reLALastUpdateOfRDAPDB.FindStringSubmatch(response)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		// 去除末尾的 " <<<" 标记
		dbUpdate := strings.TrimSpace(matchLastUpdateOfRDAPDB[1])
		domainInfo.LastUpdateOfRDAPDB = strings.TrimSuffix(dbUpdate, " <<<")
	}

	// 验证必要字段
	if domainInfo.Registrar == "" || domainInfo.CreationDate == "" || domainInfo.RegistryExpiryDate == "" {
		return structs.DomainInfo{}, utils.ErrDomainNotFound
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
		return structs.DomainInfo{}, utils.ErrDomainNotFound
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
