package whois

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/KincaidYang/whois/internal/model"
	"github.com/KincaidYang/whois/internal/utils"
)

// Registry-local zones for WHOIS responses whose timestamps carry no offset.
var (
	zoneCST = time.FixedZone("CST", 8*3600) // .cn .tw .mo (China Standard Time)
	zoneSGT = time.FixedZone("SGT", 8*3600) // .sg
	zoneJST = time.FixedZone("JST", 9*3600) // .jp
)

// 预编译正则表达式（所有解析器共享，避免每次调用重复编译）
var (
	// CN / xn--fiqs8s / xn--fiqz9s
	reCNCreationDate = regexp.MustCompile(`Registration Time: (.*)`)
	reCNExpiryDate   = regexp.MustCompile(`Expiration Time: (.*)`)
	reCNNameServer   = regexp.MustCompile(`Name Server: (.*)`)
	reCNDNSSEC       = regexp.MustCompile(`DNSSEC: (.*)`)
	reCNRegistrar    = regexp.MustCompile(`Sponsoring Registrar: (.*)`)
	reCNDomainStatus = regexp.MustCompile(`Domain Status: (.*)`)

	// HK / xn--j6w193g
	reHKCreationDate = regexp.MustCompile(`Domain Name Commencement Date: (.*)`)
	reHKExpiryDate   = regexp.MustCompile(`Expiry Date: (.*)`)
	reHKNameServer   = regexp.MustCompile(`Name Servers Information:\s*\n\n((?:.+\n)+)`)
	reHKDNSSEC       = regexp.MustCompile(`DNSSEC: (.*)`)
	reHKRegistrar    = regexp.MustCompile(`Registrar Name: (.*)`)
	reHKDomainStatus = regexp.MustCompile(`Domain Status: (.*)`)

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
	reSGCreationDate = regexp.MustCompile(`Creation Date:\s+(.*)`)
	reSGExpiryDate   = regexp.MustCompile(`Expiration Date:\s+(.*)`)
	reSGNameServer   = regexp.MustCompile(`Name Servers?:\s+(.*)`)
	reSGDNSSEC       = regexp.MustCompile(`DNSSEC:\s+(.*)`)
	reSGRegistrar    = regexp.MustCompile(`Registrar:\s+(.*)`)
	reSGDomainStatus = regexp.MustCompile(`Domain Status:\s+(.*)`)
	reSGUpdatedDate  = regexp.MustCompile(`Modified Date:\s+(.*)`)

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
	reTZSuffix         = regexp.MustCompile(`\s*\([A-Z]+\)\s*$`)
	reMultiSpace       = regexp.MustCompile(`\s+`)
)

// newDomainInfo seeds a DomainInfo with the v2 invariants shared by every
// WHOIS parser: the object class discriminator and the queried name (already
// punycode-lowercased by the handler).
func newDomainInfo(domain string) model.DomainInfo {
	return model.DomainInfo{
		ObjectClassName: model.ObjectClassDomain,
		LdhName:         strings.ToLower(domain),
	}
}

// normDate converts a registry date to RFC 3339 UTC (or RFC 3339 full-date
// when no time of day is present), interpreting zone-less timestamps in loc.
// Unrecognized formats are passed through unchanged rather than dropped.
func normDate(s string, loc *time.Location) string {
	s = strings.TrimSpace(reTZSuffix.ReplaceAllString(s, ""))
	out, _ := model.NormalizeDate(s, loc)
	return out
}

// secureDNSFromString maps a registry's DNSSEC field text to the structured
// secureDNS object. Registries phrase the signed state in several ways.
func secureDNSFromString(s string) *model.SecureDNS {
	v := strings.ToLower(strings.TrimSpace(s))
	signed := strings.HasPrefix(v, "signed") || v == "yes" || v == "active" || v == "valid"
	return &model.SecureDNS{DelegationSigned: signed}
}

// parseDSRecord parses a textual DS record ("keyTag algorithm digestType
// digest...") into a structured DSData. Returns false when the text does not
// follow that shape.
func parseDSRecord(raw string) (model.DSData, bool) {
	fields := strings.Fields(raw)
	if len(fields) < 4 {
		return model.DSData{}, false
	}
	keyTag, err1 := strconv.Atoi(fields[0])
	alg, err2 := strconv.Atoi(fields[1])
	digestType, err3 := strconv.Atoi(fields[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return model.DSData{}, false
	}
	return model.DSData{
		KeyTag:     keyTag,
		Algorithm:  alg,
		DigestType: digestType,
		Digest:     strings.Join(fields[3:], ""),
	}, true
}

// attachDSData parses raw DS text into info.SecureDNS.DSData; the signed flag
// is forced on since a DS record implies a signed delegation.
func attachDSData(info *model.DomainInfo, raw string) {
	if info.SecureDNS == nil {
		info.SecureDNS = &model.SecureDNS{}
	}
	info.SecureDNS.DelegationSigned = true
	if ds, ok := parseDSRecord(raw); ok {
		info.SecureDNS.DSData = append(info.SecureDNS.DSData, ds)
	}
}

// lowerAll lowercases every entry (nameserver hostnames are normalized to
// lowercase, matching the RDAP path).
func lowerAll(in []string) []string {
	for i, s := range in {
		in[i] = strings.ToLower(strings.TrimSpace(s))
	}
	return in
}

func ParseWhoisResponseCN(response string, domain string) (model.DomainInfo, error) {
	domainInfo := newDomainInfo(domain)

	// 解析创建日期（CNNIC 时间为北京时间，转换为 UTC）
	matchCreationDate := reCNCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.RegistrationDate = normDate(matchCreationDate[1], zoneCST)
	}

	// 解析过期日期
	matchExpiryDate := reCNExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.ExpirationDate = normDate(matchExpiryDate[1], zoneCST)
	}

	// 解析名称服务器
	matchNameServers := reCNNameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.Nameservers = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.Nameservers[i] = match[1]
		}
		domainInfo.Nameservers = lowerAll(domainInfo.Nameservers)
	}

	// 解析 DNSSEC
	matchDNSSEC := reCNDNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.SecureDNS = secureDNSFromString(matchDNSSEC[1])
	}

	// 解析注册商
	matchRegistrar := reCNRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = matchRegistrar[1]
	}

	// 解析域名状态
	matchDomainStatuses := reCNDomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.Status = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.Status[i] = match[1]
		}
		domainInfo.Status = model.CleanStatus(domainInfo.Status)
	}

	// 设置数据库更新时间为数据处理时间
	domainInfo.LastUpdateOfRdapDb = time.Now().UTC().Format(time.RFC3339)

	if domainInfo.Registrar == "" || domainInfo.RegistrationDate == "" || domainInfo.ExpirationDate == "" {
		return model.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}

func ParseWhoisResponseHK(response string, domain string) (model.DomainInfo, error) {
	domainInfo := newDomainInfo(domain)

	// 解析创建日期（HKIRC 只给日期，保持 RFC 3339 full-date）
	matchCreationDate := reHKCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.RegistrationDate = normDate(matchCreationDate[1], nil)
	}

	// 解析过期日期
	matchExpiryDate := reHKExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.ExpirationDate = normDate(matchExpiryDate[1], nil)
	}

	// 解析名称服务器
	matchNameServers := reHKNameServer.FindStringSubmatch(response)
	if len(matchNameServers) > 1 {
		nameServers := strings.Split(strings.TrimSpace(matchNameServers[1]), "\n")
		domainInfo.Nameservers = lowerAll(nameServers)
	}

	// 解析 DNSSEC
	matchDNSSEC := reHKDNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.SecureDNS = secureDNSFromString(matchDNSSEC[1])
	}

	// 解析注册商
	matchRegistrar := reHKRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = matchRegistrar[1]
	}

	// 解析域名状态
	matchDomainStatus := reHKDomainStatus.FindStringSubmatch(response)
	if len(matchDomainStatus) > 1 {
		domainInfo.Status = model.CleanStatus([]string{matchDomainStatus[1]})
	}

	// 设置数据库更新时间为数据处理时间
	domainInfo.LastUpdateOfRdapDb = time.Now().UTC().Format(time.RFC3339)

	if domainInfo.Registrar == "" || domainInfo.RegistrationDate == "" || domainInfo.ExpirationDate == "" {
		return model.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}

func ParseWhoisResponseTW(response string, domain string) (model.DomainInfo, error) {
	domainInfo := newDomainInfo(domain)

	// 解析注册商
	matchRegistrar := reTWRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = strings.TrimSpace(matchRegistrar[1])
	}

	// 解析域名状态
	matchDomainStatuses := reTWDomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.Status = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.Status[i] = strings.TrimSpace(match[1])
		}
		domainInfo.Status = model.CleanStatus(domainInfo.Status)
	}

	// 解析创建日期（TWNIC 时间为台北时间，转换为 UTC）
	matchCreationDate := reTWCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.RegistrationDate = normDate(matchCreationDate[1], zoneCST)
	}

	// 解析过期日期
	matchExpiryDate := reTWExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.ExpirationDate = normDate(matchExpiryDate[1], zoneCST)
	}

	// 解析名称服务器
	matchNameServers := reTWNameServer.FindStringSubmatch(response)
	if len(matchNameServers) > 1 {
		servers := strings.Split(strings.TrimSpace(matchNameServers[1]), "\n")
		domainInfo.Nameservers = lowerAll(servers)
	}

	// 解析 DNSSEC
	matchDNSSEC := reTWDNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.SecureDNS = secureDNSFromString(matchDNSSEC[1])
	}

	// 设置数据库更新时间为数据处理时间
	domainInfo.LastUpdateOfRdapDb = time.Now().UTC().Format(time.RFC3339)

	if domainInfo.Registrar == "" || domainInfo.RegistrationDate == "" || domainInfo.ExpirationDate == "" {
		return model.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}

func ParseWhoisResponseSO(response string, domain string) (model.DomainInfo, error) {
	domainInfo := newDomainInfo(domain)

	// 解析注册商
	matchRegistrar := reSORegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = matchRegistrar[1]
	}

	// 解析域名状态
	matchDomainStatuses := reSODomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.Status = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.Status[i] = match[1]
		}
		domainInfo.Status = model.CleanStatus(domainInfo.Status)
	}

	// 解析 Registrar IANA ID
	matchRegistrarIANAID := reSORegistrarIANAID.FindStringSubmatch(response)
	if len(matchRegistrarIANAID) > 1 {
		domainInfo.RegistrarIANAID = matchRegistrarIANAID[1]
	}

	// 解析创建日期
	matchCreationDate := reSOCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.RegistrationDate = normDate(matchCreationDate[1], time.UTC)
	}

	// 解析过期日期
	matchExpiryDate := reSOExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.ExpirationDate = normDate(matchExpiryDate[1], time.UTC)
	}

	// 解析更新日期
	matchUpdatedDate := reSOUpdatedDate.FindStringSubmatch(response)
	if len(matchUpdatedDate) > 1 {
		domainInfo.LastChangedDate = normDate(matchUpdatedDate[1], time.UTC)
	}

	// 解析名称服务器
	matchNameServers := reSONameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.Nameservers = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.Nameservers[i] = match[1]
		}
		domainInfo.Nameservers = lowerAll(domainInfo.Nameservers)
	}

	// 解析 DNSSEC
	matchDNSSEC := reSODNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.SecureDNS = secureDNSFromString(matchDNSSEC[1])
	}

	// 解析 DNSSEC DS Data
	matchDNSSecDSData := reSODNSSecDSData.FindStringSubmatch(response)
	if len(matchDNSSecDSData) > 1 {
		attachDSData(&domainInfo, matchDNSSecDSData[1])
	}

	// 解析数据库更新时间
	matchLastUpdateOfRDAPDB := reSOLastUpdateOfRDAPDB.FindStringSubmatch(response)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		domainInfo.LastUpdateOfRdapDb = normDate(strings.TrimSuffix(matchLastUpdateOfRDAPDB[1], " <<<"), time.UTC)
	}

	if domainInfo.Registrar == "" || domainInfo.RegistrationDate == "" || domainInfo.ExpirationDate == "" {
		return model.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}

func ParseWhoisResponseRU(response string, domain string) (model.DomainInfo, error) {
	domainInfo := newDomainInfo(domain)

	// 解析注册商
	matchRegistrar := reRURegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = strings.TrimSpace(matchRegistrar[1])
	}

	// 解析创建日期
	matchCreationDate := reRUCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.RegistrationDate = normDate(matchCreationDate[1], time.UTC)
	}

	// 解析过期日期
	matchExpiryDate := reRUExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.ExpirationDate = normDate(matchExpiryDate[1], time.UTC)
	}

	// 解析名称服务器
	matchNameServers := reRUNameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.Nameservers = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.Nameservers[i] = match[1]
		}
		domainInfo.Nameservers = lowerAll(domainInfo.Nameservers)
	}

	// 解析域名状态
	matchDomainStatuses := reRUDomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.Status = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.Status[i] = match[1]
		}
		domainInfo.Status = model.CleanStatus(domainInfo.Status)
	}

	// 解析数据库更新时间
	matchLastUpdateOfRDAPDB := reRULastUpdateOfRDAPDB.FindStringSubmatch(response)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		domainInfo.LastUpdateOfRdapDb = normDate(matchLastUpdateOfRDAPDB[1], time.UTC)
	}

	if domainInfo.Registrar == "" || domainInfo.RegistrationDate == "" || domainInfo.ExpirationDate == "" {
		return model.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}

func ParseWhoisResponseSB(response string, domain string) (model.DomainInfo, error) {
	domainInfo := newDomainInfo(domain)

	// 解析创建日期
	matchCreationDate := reSBCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.RegistrationDate = normDate(matchCreationDate[1], time.UTC)
	}

	// 解析过期日期
	matchExpiryDate := reSBExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.ExpirationDate = normDate(matchExpiryDate[1], time.UTC)
	}

	// 解析更新日期
	matchUpdatedDate := reSBUpdatedDate.FindStringSubmatch(response)
	if len(matchUpdatedDate) > 1 {
		domainInfo.LastChangedDate = normDate(matchUpdatedDate[1], time.UTC)
	}

	// 解析名称服务器
	matchNameServers := reSBNameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.Nameservers = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.Nameservers[i] = match[1]
		}
		domainInfo.Nameservers = lowerAll(domainInfo.Nameservers)
	}

	// 解析 DNSSEC
	matchDNSSEC := reSBDNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.SecureDNS = secureDNSFromString(matchDNSSEC[1])
	}

	// 解析注册商
	matchRegistrar := reSBRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = matchRegistrar[1]
	}

	// 解析域名状态
	matchDomainStatuses := reSBDomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.Status = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.Status[i] = match[1]
		}
		domainInfo.Status = model.CleanStatus(domainInfo.Status)
	}

	// 解析 Registrar IANA ID
	matchRegistrarIANAID := reSBRegistrarIANAID.FindStringSubmatch(response)
	if len(matchRegistrarIANAID) > 1 {
		domainInfo.RegistrarIANAID = matchRegistrarIANAID[1]
	}

	// 解析 DNSSEC DS Data
	matchDNSSecDSData := reSBDNSSecDSData.FindStringSubmatch(response)
	if len(matchDNSSecDSData) > 1 {
		attachDSData(&domainInfo, matchDNSSecDSData[1])
	}

	// 解析数据库更新时间
	matchLastUpdateOfRDAPDB := reSBLastUpdateOfRDAPDB.FindStringSubmatch(response)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		domainInfo.LastUpdateOfRdapDb = normDate(strings.TrimSuffix(matchLastUpdateOfRDAPDB[1], " <<<"), time.UTC)
	}

	if domainInfo.Registrar == "" || domainInfo.RegistrationDate == "" || domainInfo.ExpirationDate == "" {
		return model.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}

func ParseWhoisResponseMO(response string, domain string) (model.DomainInfo, error) {
	domainInfo := newDomainInfo(domain)

	// Parse creation date (MONIC local time is UTC+8)
	matchCreationDate := reMOCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.RegistrationDate = normDate(matchCreationDate[1], zoneCST)
	}

	// Parse expiry date
	matchExpiryDate := reMOExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.ExpirationDate = normDate(matchExpiryDate[1], zoneCST)
	}

	// Parse name servers
	matchNameServers := reMONameServer.FindStringSubmatch(response)
	if len(matchNameServers) > 1 {
		nameServers := strings.Split(strings.TrimSpace(matchNameServers[1]), "\n")
		domainInfo.Nameservers = lowerAll(nameServers)
	}

	// 设置数据库更新时间为数据处理时间
	domainInfo.LastUpdateOfRdapDb = time.Now().UTC().Format(time.RFC3339)

	if domainInfo.RegistrationDate == "" || domainInfo.ExpirationDate == "" {
		return model.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}

func ParseWhoisResponseAU(response string, domain string) (model.DomainInfo, error) {
	domainInfo := newDomainInfo(domain)

	// 清理响应数据
	cleanedResponse := strings.ReplaceAll(response, "\r", "")

	// 解析创建日期
	matchCreationDate := reAUCreationDate.FindStringSubmatch(cleanedResponse)
	if len(matchCreationDate) > 1 {
		domainInfo.RegistrationDate = normDate(matchCreationDate[1], time.UTC)
	}

	// 解析过期日期
	matchExpiryDate := reAUExpiryDate.FindStringSubmatch(cleanedResponse)
	if len(matchExpiryDate) > 1 {
		domainInfo.ExpirationDate = normDate(matchExpiryDate[1], time.UTC)
	}

	// 解析更新日期
	matchUpdatedDate := reAUUpdatedDate.FindStringSubmatch(cleanedResponse)
	if len(matchUpdatedDate) > 1 {
		domainInfo.LastChangedDate = normDate(matchUpdatedDate[1], time.UTC)
	}

	// 解析名称服务器
	matchNameServers := reAUNameServer.FindAllStringSubmatch(cleanedResponse, -1)
	if len(matchNameServers) > 0 {
		domainInfo.Nameservers = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.Nameservers[i] = match[1]
		}
		domainInfo.Nameservers = lowerAll(domainInfo.Nameservers)
	}

	// 解析 DNSSEC
	matchDNSSEC := reAUDNSSEC.FindStringSubmatch(cleanedResponse)
	if len(matchDNSSEC) > 1 {
		domainInfo.SecureDNS = secureDNSFromString(matchDNSSEC[1])
	}

	// 解析注册商
	matchRegistrar := reAURegistrar.FindStringSubmatch(cleanedResponse)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = strings.TrimSpace(matchRegistrar[1])
	}

	// 解析域名状态
	matchDomainStatuses := reAUDomainStatus.FindAllStringSubmatch(cleanedResponse, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.Status = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.Status[i] = strings.TrimSpace(match[1])
		}
		domainInfo.Status = model.CleanStatus(domainInfo.Status)
	}

	// 注册商 IANA ID 在给定示例中未提供，若需要解析请确保有正确格式的数据并使用相应正则表达式
	matchRegistrarIANAID := reAURegistrarIANAID.FindStringSubmatch(cleanedResponse)
	if len(matchRegistrarIANAID) > 1 {
		domainInfo.RegistrarIANAID = matchRegistrarIANAID[1]
	}

	// 解析 DNSSEC DS Data
	matchDNSSecDSData := reAUDNSSecDSData.FindStringSubmatch(cleanedResponse)
	if len(matchDNSSecDSData) > 1 {
		attachDSData(&domainInfo, matchDNSSecDSData[1])
	}

	// 解析 Last update of WHOIS database
	matchLastUpdateOfRDAPDB := reAULastUpdateOfRDAPDB.FindStringSubmatch(cleanedResponse)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		domainInfo.LastUpdateOfRdapDb = normDate(matchLastUpdateOfRDAPDB[1], time.UTC)
	}

	if domainInfo.Registrar == "" {
		return model.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}

func ParseWhoisResponseSG(response string, domain string) (model.DomainInfo, error) {
	domainInfo := newDomainInfo(domain)

	// 解析创建日期（SGNIC 时间为新加坡时间，转换为 UTC）
	matchCreationDate := reSGCreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.RegistrationDate = normDate(strings.TrimRight(matchCreationDate[1], "\r"), zoneSGT)
	}

	// 解析过期日期
	matchExpiryDate := reSGExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.ExpirationDate = normDate(strings.TrimRight(matchExpiryDate[1], "\r"), zoneSGT)
	}

	// 解析更新日期
	matchUpdatedDate := reSGUpdatedDate.FindStringSubmatch(response)
	if len(matchUpdatedDate) > 1 {
		domainInfo.LastChangedDate = normDate(strings.TrimRight(matchUpdatedDate[1], "\r"), zoneSGT)
	}

	// 解析名称服务器
	matchNameServers := reSGNameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.Nameservers = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.Nameservers[i] = strings.TrimRight(match[1], "\r")
		}
		domainInfo.Nameservers = lowerAll(domainInfo.Nameservers)
	}

	// 解析 DNSSEC
	matchDNSSEC := reSGDNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.SecureDNS = secureDNSFromString(strings.TrimRight(matchDNSSEC[1], "\r\t"))
	}

	// 解析注册商
	matchRegistrar := reSGRegistrar.FindStringSubmatch(response)
	if len(matchRegistrar) > 1 {
		domainInfo.Registrar = strings.TrimRight(matchRegistrar[1], "\r")
	}

	// 解析域名状态
	matchDomainStatuses := reSGDomainStatus.FindAllStringSubmatch(response, -1)
	if len(matchDomainStatuses) > 0 {
		domainInfo.Status = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.Status[i] = strings.TrimRight(match[1], "\r")
		}
		domainInfo.Status = model.CleanStatus(domainInfo.Status)
	}

	if domainInfo.Registrar == "" || domainInfo.RegistrationDate == "" || domainInfo.ExpirationDate == "" {
		return model.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}

func ParseWhoisResponseLA(response string, domain string) (model.DomainInfo, error) {
	domainInfo := newDomainInfo(domain)

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
		domainInfo.Status = make([]string, len(matchDomainStatuses))
		for i, match := range matchDomainStatuses {
			domainInfo.Status[i] = strings.TrimSpace(match[1])
		}
		domainInfo.Status = model.CleanStatus(domainInfo.Status)
	}

	// 解析创建日期
	matchCreationDate := reLACreationDate.FindStringSubmatch(response)
	if len(matchCreationDate) > 1 {
		domainInfo.RegistrationDate = normDate(matchCreationDate[1], time.UTC)
	}

	// 解析过期日期
	matchExpiryDate := reLAExpiryDate.FindStringSubmatch(response)
	if len(matchExpiryDate) > 1 {
		domainInfo.ExpirationDate = normDate(matchExpiryDate[1], time.UTC)
	}

	// 解析更新日期
	matchUpdatedDate := reLAUpdatedDate.FindStringSubmatch(response)
	if len(matchUpdatedDate) > 1 {
		domainInfo.LastChangedDate = normDate(matchUpdatedDate[1], time.UTC)
	}

	// 解析名称服务器
	matchNameServers := reLANameServer.FindAllStringSubmatch(response, -1)
	if len(matchNameServers) > 0 {
		domainInfo.Nameservers = make([]string, len(matchNameServers))
		for i, match := range matchNameServers {
			domainInfo.Nameservers[i] = strings.TrimSpace(match[1])
		}
		domainInfo.Nameservers = lowerAll(domainInfo.Nameservers)
	}

	// 解析 DNSSEC
	matchDNSSEC := reLADNSSEC.FindStringSubmatch(response)
	if len(matchDNSSEC) > 1 {
		domainInfo.SecureDNS = secureDNSFromString(matchDNSSEC[1])
	}

	// 解析数据库更新时间
	matchLastUpdateOfRDAPDB := reLALastUpdateOfRDAPDB.FindStringSubmatch(response)
	if len(matchLastUpdateOfRDAPDB) > 1 {
		// 去除末尾的 " <<<" 标记
		dbUpdate := strings.TrimSpace(matchLastUpdateOfRDAPDB[1])
		domainInfo.LastUpdateOfRdapDb = normDate(strings.TrimSuffix(dbUpdate, " <<<"), time.UTC)
	}

	// 验证必要字段
	if domainInfo.Registrar == "" || domainInfo.RegistrationDate == "" || domainInfo.ExpirationDate == "" {
		return model.DomainInfo{}, utils.ErrDomainNotFound
	}

	return domainInfo, nil
}

// ParseWhoisResponseJP parses WHOIS response for .jp domains (including .co.jp and other variants)
func ParseWhoisResponseJP(response string, domain string) (model.DomainInfo, error) {
	domainInfo := newDomainInfo(domain)

	// 解析域名 - 尝试两种格式
	if name := matchFirstGroup(reJPDomainName, response,
		func() string { return matchFirstGroup(reJPDomainNameAlt, response, nil) }); name != "" {
		domainInfo.LdhName = strings.ToLower(name)
	}

	// 解析注册人/组织 - 尝试两种格式
	domainInfo.Registrar = matchFirstGroup(reJPRegistrant, response,
		func() string { return matchFirstGroup(reJPOrganization, response, nil) })

	// 解析名称服务器 - 尝试两种格式
	domainInfo.Nameservers = matchAllFirstGroup(reJPNameServer, response)
	if len(domainInfo.Nameservers) == 0 {
		domainInfo.Nameservers = matchAllFirstGroup(reJPNameServerAlt, response)
	}
	domainInfo.Nameservers = lowerAll(domainInfo.Nameservers)

	// 解析 DNSSEC - 支持 [Signing Key] 和 s. [署名鍵] 两种格式
	domainInfo.SecureDNS = &model.SecureDNS{}
	if signingKeyRaw := extractSigningKey(response); signingKeyRaw != "" {
		attachDSData(&domainInfo, signingKeyRaw)
	}

	// 解析注册日期 (格式: 2001/05/23)
	if dateStr := matchFirstGroup(reJPCreationDate, response, nil); dateStr != "" {
		domainInfo.RegistrationDate = normDate(dateStr, zoneJST)
	}

	// 解析过期日期 - 优先 [有効期限] 字段，再从 [状態] 中提取
	if dateStr := matchFirstGroup(reJPExpiryDate, response, nil); dateStr != "" {
		domainInfo.ExpirationDate = normDate(dateStr, zoneJST)
	}

	// 解析 [状態] - 同时提取过期日期(如有)和状态文本
	var statuses []string
	if statusStr := matchFirstGroup(reJPStatus, response, nil); statusStr != "" {
		// 从状态中提取过期日期 (适用于 co.jp: "Connected (2026/10/31)")
		if domainInfo.ExpirationDate == "" {
			if matchExpiry := reJPExpiryInStatus.FindStringSubmatch(statusStr); len(matchExpiry) > 1 {
				domainInfo.ExpirationDate = normDate(matchExpiry[1], zoneJST)
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
		domainInfo.Status = model.CleanStatus(statuses)
	}

	// 解析最终更新时间 (格式: 2025/06/01 01:05:04 (JST))
	if dateStr := matchFirstGroup(reJPUpdatedDate, response, nil); dateStr != "" {
		domainInfo.LastChangedDate = normDate(dateStr, zoneJST)
	}

	// 设置数据库更新时间为当前时间
	domainInfo.LastUpdateOfRdapDb = time.Now().UTC().Format(time.RFC3339)

	// 验证必要字段
	if domainInfo.RegistrationDate == "" || domainInfo.ExpirationDate == "" {
		return model.DomainInfo{}, utils.ErrDomainNotFound
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
