package whois

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/KincaidYang/whois/internal/model"
	"github.com/KincaidYang/whois/internal/utils"
)

func TestParseWhoisResponseCN(t *testing.T) {
	response := `Registration Time: 2025-03-01 12:00:00
Expiration Time: 2026-03-01 12:00:00
Name Server: ns1.example.com
Name Server: ns2.example.com
DNSSEC: unsigned
Sponsoring Registrar: Example Registrar
Domain Status: active`

	domain := "example.cn"
	expected := model.DomainInfo{
		ObjectClassName:  model.ObjectClassDomain,
		LdhName:          domain,
		RegistrationDate: "2025-03-01T04:00:00Z", // Converted from CST to UTC
		ExpirationDate:   "2026-03-01T04:00:00Z",
		Nameservers:      []string{"ns1.example.com", "ns2.example.com"},
		SecureDNS:        &model.SecureDNS{DelegationSigned: false},
		Registrar:        "Example Registrar",
		Status:           []string{"active"},
	}

	domainInfo, err := ParseWhoisResponseCN(response, domain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Validate that LastUpdateOfRdapDb is a valid RFC3339 timestamp
	if _, err := time.Parse(time.RFC3339, domainInfo.LastUpdateOfRdapDb); err != nil {
		t.Errorf("LastUpdateOfRdapDb is not a valid RFC3339 timestamp: %v", domainInfo.LastUpdateOfRdapDb)
	}

	// Ignore LastUpdateOfRdapDb field for comparison
	domainInfo.LastUpdateOfRdapDb = ""
	if !reflect.DeepEqual(domainInfo, expected) {
		t.Errorf("expected %+v, got %+v", expected, domainInfo)
	}
}

func TestParseWhoisResponseLA(t *testing.T) {
	// 测试用的原始 Whois 响应数据
	response := `Domain Name: NIC.LA
Registry Domain ID: D472370-LANIC
Registrar WHOIS Server: whois.nic.la
Registrar URL:
Updated Date: 2016-10-17T04:13:14.0Z
Creation Date: 2000-11-20T01:00:00.0Z
Registry Expiry Date: 2026-11-20T23:59:59.0Z
Registrar: TLD Registrar Solutions Ltd
Registrar IANA ID:
Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited
Domain Status: serverRenewProhibited https://icann.org/epp#serverRenewProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registrant Email: https://whois.nic.la/contact/nic.la/registrant
Admin Email: https://whois.nic.la/contact/nic.la/admin
Tech Email: https://whois.nic.la/contact/nic.la/tech
Name Server: NS0.CENTRALNIC-DNS.COM
Name Server: NS1.CENTRALNIC-DNS.COM
Name Server: NS2.CENTRALNIC-DNS.COM
Name Server: NS3.CENTRALNIC-DNS.COM
Name Server: NS4.CENTRALNIC-DNS.COM
Name Server: NS5.CENTRALNIC-DNS.COM
DNSSEC: unsigned
Registrar Abuse Contact Email: abuse@centralnic.com
Registrar Abuse Contact Phone: +44.2033880600
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of WHOIS database: 2025-10-12T05:44:20.0Z <<<`

	domain := "nic.la"
	domainInfo, err := ParseWhoisResponseLA(response, domain)

	if err != nil {
		t.Fatalf("ParseWhoisResponseLA returned an error: %v", err)
	}

	// 验证域名
	if domainInfo.LdhName != domain {
		t.Errorf("Expected ldhName %s, got %s", domain, domainInfo.LdhName)
	}

	// 验证注册商
	expectedRegistrar := "TLD Registrar Solutions Ltd"
	if domainInfo.Registrar != expectedRegistrar {
		t.Errorf("Expected registrar %s, got %s", expectedRegistrar, domainInfo.Registrar)
	}

	// 验证创建日期（归一化为 RFC 3339 UTC，小数秒被丢弃）
	expectedCreationDate := "2000-11-20T01:00:00Z"
	if domainInfo.RegistrationDate != expectedCreationDate {
		t.Errorf("Expected registration date %s, got %s", expectedCreationDate, domainInfo.RegistrationDate)
	}

	// 验证过期日期
	expectedExpiryDate := "2026-11-20T23:59:59Z"
	if domainInfo.ExpirationDate != expectedExpiryDate {
		t.Errorf("Expected expiration date %s, got %s", expectedExpiryDate, domainInfo.ExpirationDate)
	}

	// 验证更新日期
	expectedUpdatedDate := "2016-10-17T04:13:14Z"
	if domainInfo.LastChangedDate != expectedUpdatedDate {
		t.Errorf("Expected lastChanged date %s, got %s", expectedUpdatedDate, domainInfo.LastChangedDate)
	}

	// 验证名称服务器（统一小写）
	expectedNameServers := []string{
		"ns0.centralnic-dns.com",
		"ns1.centralnic-dns.com",
		"ns2.centralnic-dns.com",
		"ns3.centralnic-dns.com",
		"ns4.centralnic-dns.com",
		"ns5.centralnic-dns.com",
	}
	if !reflect.DeepEqual(domainInfo.Nameservers, expectedNameServers) {
		t.Errorf("Nameservers: got %v, want %v", domainInfo.Nameservers, expectedNameServers)
	}

	// 验证 DNSSEC
	if domainInfo.SecureDNS == nil || domainInfo.SecureDNS.DelegationSigned {
		t.Errorf("SecureDNS: got %+v, want unsigned", domainInfo.SecureDNS)
	}

	// 验证域名状态（EPP 引用 URL 被剥离）
	expectedStatuses := []string{
		"serverTransferProhibited",
		"serverUpdateProhibited",
		"serverDeleteProhibited",
		"serverRenewProhibited",
		"clientTransferProhibited",
	}
	if !reflect.DeepEqual(domainInfo.Status, expectedStatuses) {
		t.Errorf("Status: got %v, want %v", domainInfo.Status, expectedStatuses)
	}

	// 验证数据库最后更新时间（归一化为 RFC 3339 UTC）
	expectedDBUpdate := "2025-10-12T05:44:20Z"
	if domainInfo.LastUpdateOfRdapDb != expectedDBUpdate {
		t.Errorf("Expected last update of DB %s, got %s", expectedDBUpdate, domainInfo.LastUpdateOfRdapDb)
	}

	// 验证 Registrar IANA ID 为空（因为原始数据中是空的）
	if domainInfo.RegistrarIANAID != "" {
		t.Errorf("Expected empty Registrar IANA ID, got %s", domainInfo.RegistrarIANAID)
	}
}

func TestParseWhoisResponseLA_DomainNotFound(t *testing.T) {
	response := `Domain Name: NOTFOUND.LA
Registry Domain ID:
Registrar WHOIS Server:
Registrar URL:
Updated Date:
Creation Date:
Registry Expiry Date:
Name Server: NS1.EXAMPLE.COM
DNSSEC: unsigned
>>> Last update of WHOIS database: 2025-10-12T04:26:45.0Z <<<`

	domain := "notfound.la"
	_, err := ParseWhoisResponseLA(response, domain)

	if err == nil {
		t.Error("Expected error for domain not found, but got nil")
		return
	}

	if !errors.Is(err, utils.ErrDomainNotFound) {
		t.Errorf("Expected ErrDomainNotFound, got %v", err)
	}
}

func TestParseWhoisResponseHK(t *testing.T) {
	response := "Domain Name: example.hk\n" +
		"Domain Name Commencement Date: 01-03-2010\n" +
		"Expiry Date: 01-03-2026\n" +
		"Registrar Name: Example HK Registrar\n" +
		"Domain Status: Active\n" +
		"DNSSEC: unsigned\n" +
		"Name Servers Information:\n" +
		"\n" +
		"ns1.example.com\n" +
		"ns2.example.com\n"

	domain := "example.hk"
	info, err := ParseWhoisResponseHK(response, domain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.LdhName != domain {
		t.Errorf("LdhName: got %q, want %q", info.LdhName, domain)
	}
	if info.Registrar != "Example HK Registrar" {
		t.Errorf("Registrar: got %q", info.Registrar)
	}
	if info.RegistrationDate != "2010-03-01" {
		t.Errorf("RegistrationDate: got %q, want 2010-03-01", info.RegistrationDate)
	}
	if info.ExpirationDate != "2026-03-01" {
		t.Errorf("ExpirationDate: got %q, want 2026-03-01", info.ExpirationDate)
	}
	if info.SecureDNS == nil || info.SecureDNS.DelegationSigned {
		t.Errorf("SecureDNS: got %+v, want unsigned", info.SecureDNS)
	}
}

func TestParseWhoisResponseHK_NotFound(t *testing.T) {
	response := "Domain Name: notfound.hk\r\nDomain Status: Not Registered\r\n"
	_, err := ParseWhoisResponseHK(response, "notfound.hk")
	if !errors.Is(err, utils.ErrDomainNotFound) {
		t.Errorf("expected ErrDomainNotFound, got %v", err)
	}
}

func TestParseWhoisResponseTW(t *testing.T) {
	response := `Registration Service Provider: Example TW Registrar
Domain Status: active
Record created on 2010-03-01 08:00:00
Record expires on 2026-03-01 08:00:00
DNSSEC: unsigned
Domain servers in listed order:
   ns1.example.com
   ns2.example.com

`
	domain := "example.tw"
	info, err := ParseWhoisResponseTW(response, domain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Registrar != "Example TW Registrar" {
		t.Errorf("Registrar: got %q", info.Registrar)
	}
	// Dates converted from CST (UTC+8) to UTC: 08:00:00 CST = 00:00:00 UTC
	if info.RegistrationDate != "2010-03-01T00:00:00Z" {
		t.Errorf("RegistrationDate: got %q, want 2010-03-01T00:00:00Z", info.RegistrationDate)
	}
	if info.ExpirationDate != "2026-03-01T00:00:00Z" {
		t.Errorf("ExpirationDate: got %q, want 2026-03-01T00:00:00Z", info.ExpirationDate)
	}
	if len(info.Status) == 0 || info.Status[0] != "active" {
		t.Errorf("Status: got %v", info.Status)
	}
	if len(info.Nameservers) != 2 {
		t.Errorf("Nameservers count: got %d, want 2", len(info.Nameservers))
	}
}

func TestParseWhoisResponseTW_NotFound(t *testing.T) {
	response := `No match for "NOTFOUND.TW".`
	_, err := ParseWhoisResponseTW(response, "notfound.tw")
	if !errors.Is(err, utils.ErrDomainNotFound) {
		t.Errorf("expected ErrDomainNotFound, got %v", err)
	}
}

func TestParseWhoisResponseSO(t *testing.T) {
	response := `Registrar: Example SO Registrar
Domain Status: active
Registrar IANA ID: 1234
Creation Date: 2010-03-01T00:00:00Z
Registry Expiry Date: 2026-03-01T00:00:00Z
Updated Date: 2025-01-01T00:00:00Z
Name Server: ns1.example.so
Name Server: ns2.example.so
DNSSEC: unsigned
Last update of WHOIS database: 2025-10-12T05:44:20Z <<<`

	domain := "example.so"
	info, err := ParseWhoisResponseSO(response, domain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Registrar != "Example SO Registrar" {
		t.Errorf("Registrar: got %q", info.Registrar)
	}
	if info.RegistrationDate != "2010-03-01T00:00:00Z" {
		t.Errorf("RegistrationDate: got %q", info.RegistrationDate)
	}
	if info.ExpirationDate != "2026-03-01T00:00:00Z" {
		t.Errorf("ExpirationDate: got %q", info.ExpirationDate)
	}
	if info.RegistrarIANAID != "1234" {
		t.Errorf("RegistrarIANAID: got %q", info.RegistrarIANAID)
	}
	if len(info.Nameservers) != 2 {
		t.Errorf("Nameservers count: got %d, want 2", len(info.Nameservers))
	}
}

func TestParseWhoisResponseSO_NotFound(t *testing.T) {
	response := `Domain Status: available`
	_, err := ParseWhoisResponseSO(response, "notfound.so")
	if !errors.Is(err, utils.ErrDomainNotFound) {
		t.Errorf("expected ErrDomainNotFound, got %v", err)
	}
}

func TestParseWhoisResponseRU(t *testing.T) {
	response := `% WHOIS server

domain: EXAMPLE.RU
nserver: ns1.example.ru
nserver: ns2.example.ru
state: REGISTERED, DELEGATED
registrar: Example RU Registrar
created: 2010-03-01T00:00:00Z
paid-till: 2026-03-01T00:00:00Z
Last updated on 2025-10-12T05:44:20Z`

	domain := "example.ru"
	info, err := ParseWhoisResponseRU(response, domain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Registrar != "Example RU Registrar" {
		t.Errorf("Registrar: got %q", info.Registrar)
	}
	if info.RegistrationDate != "2010-03-01T00:00:00Z" {
		t.Errorf("RegistrationDate: got %q", info.RegistrationDate)
	}
	if info.ExpirationDate != "2026-03-01T00:00:00Z" {
		t.Errorf("ExpirationDate: got %q", info.ExpirationDate)
	}
	if len(info.Nameservers) != 2 {
		t.Errorf("Nameservers count: got %d, want 2", len(info.Nameservers))
	}
	if len(info.Status) == 0 {
		t.Error("Status is empty")
	}
}

func TestParseWhoisResponseRU_NotFound(t *testing.T) {
	response := `% No entries found for the selected source(s).`
	_, err := ParseWhoisResponseRU(response, "notfound.ru")
	if !errors.Is(err, utils.ErrDomainNotFound) {
		t.Errorf("expected ErrDomainNotFound, got %v", err)
	}
}

func TestParseWhoisResponseSB(t *testing.T) {
	response := `Registrar: Example SB Registrar
Domain Status: active
Registrar IANA ID: 5678
Creation Date: 2010-03-01T00:00:00Z
Registry Expiry Date: 2026-03-01T00:00:00Z
Updated Date: 2025-01-01T00:00:00Z
Name Server: ns1.example.sb
DNSSEC: unsigned
Last update of WHOIS database: 2025-10-12T05:44:20Z <<<`

	domain := "example.sb"
	info, err := ParseWhoisResponseSB(response, domain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Registrar != "Example SB Registrar" {
		t.Errorf("Registrar: got %q", info.Registrar)
	}
	if info.RegistrationDate != "2010-03-01T00:00:00Z" {
		t.Errorf("RegistrationDate: got %q", info.RegistrationDate)
	}
	if info.ExpirationDate != "2026-03-01T00:00:00Z" {
		t.Errorf("ExpirationDate: got %q", info.ExpirationDate)
	}
}

func TestParseWhoisResponseSB_NotFound(t *testing.T) {
	response := `Domain Status: available`
	_, err := ParseWhoisResponseSB(response, "notfound.sb")
	if !errors.Is(err, utils.ErrDomainNotFound) {
		t.Errorf("expected ErrDomainNotFound, got %v", err)
	}
}

func TestParseWhoisResponseMO(t *testing.T) {
	response := `
Record created on 2010-03-01
Record expires on 2026-03-01

Domain name servers:
 ---
 ns1.example.mo
 ns2.example.mo

`
	domain := "example.mo"
	info, err := ParseWhoisResponseMO(response, domain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.LdhName != domain {
		t.Errorf("LdhName: got %q", info.LdhName)
	}
	if info.RegistrationDate != "2010-03-01" {
		t.Errorf("RegistrationDate: got %q", info.RegistrationDate)
	}
	if info.ExpirationDate != "2026-03-01" {
		t.Errorf("ExpirationDate: got %q", info.ExpirationDate)
	}
	if len(info.Nameservers) != 2 {
		t.Errorf("Nameservers count: got %d, want 2", len(info.Nameservers))
	}
}

func TestParseWhoisResponseMO_NotFound(t *testing.T) {
	response := `No object found.`
	_, err := ParseWhoisResponseMO(response, "notfound.mo")
	if !errors.Is(err, utils.ErrDomainNotFound) {
		t.Errorf("expected ErrDomainNotFound, got %v", err)
	}
}

func TestParseWhoisResponseAU(t *testing.T) {
	response := "Registrar Name: Example AU Registrar\r\n" +
		"Registrar IANA ID: 9012\r\n" +
		"Status: serverHold\r\n" +
		"Creation Date: 2010-03-01T00:00:00Z\r\n" +
		"Registry Expiry Date: 2026-03-01T00:00:00Z\r\n" +
		"Last Modified: 2025-01-01T00:00:00Z\r\n" +
		"Name Server: ns1.example.au\r\n" +
		"Name Server: ns2.example.au\r\n" +
		"DNSSEC: unsigned\r\n" +
		"Last update of WHOIS database: 2025-10-12T00:00:00Z\r\n"

	domain := "example.com.au"
	info, err := ParseWhoisResponseAU(response, domain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Registrar != "Example AU Registrar" {
		t.Errorf("Registrar: got %q", info.Registrar)
	}
	if info.RegistrationDate != "2010-03-01T00:00:00Z" {
		t.Errorf("RegistrationDate: got %q", info.RegistrationDate)
	}
	if info.ExpirationDate != "2026-03-01T00:00:00Z" {
		t.Errorf("ExpirationDate: got %q", info.ExpirationDate)
	}
	if len(info.Nameservers) != 2 {
		t.Errorf("Nameservers count: got %d, want 2", len(info.Nameservers))
	}
	if len(info.Status) == 0 || info.Status[0] != "serverHold" {
		t.Errorf("Status: got %v", info.Status)
	}
}

func TestParseWhoisResponseAU_NotFound(t *testing.T) {
	response := "% No Data Found\r\n"
	_, err := ParseWhoisResponseAU(response, "notfound.com.au")
	if !errors.Is(err, utils.ErrDomainNotFound) {
		t.Errorf("expected ErrDomainNotFound, got %v", err)
	}
}

func TestParseWhoisResponseSG(t *testing.T) {
	response := "Registrar: Example SG Registrar\r\n" +
		"Domain Status: Active\r\n" +
		"Creation Date: 2010-03-01T00:00:00Z\r\n" +
		"Expiration Date: 2026-03-01T00:00:00Z\r\n" +
		"Modified Date: 2025-01-01T00:00:00Z\r\n" +
		"Name Servers: ns1.example.sg\r\n" +
		"Name Servers: ns2.example.sg\r\n" +
		"DNSSEC: unsigned\r\n"

	domain := "example.sg"
	info, err := ParseWhoisResponseSG(response, domain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Registrar != "Example SG Registrar" {
		t.Errorf("Registrar: got %q", info.Registrar)
	}
	if info.RegistrationDate != "2010-03-01T00:00:00Z" {
		t.Errorf("RegistrationDate: got %q", info.RegistrationDate)
	}
	if info.ExpirationDate != "2026-03-01T00:00:00Z" {
		t.Errorf("ExpirationDate: got %q", info.ExpirationDate)
	}
	if len(info.Nameservers) != 2 {
		t.Errorf("Nameservers count: got %d, want 2", len(info.Nameservers))
	}
}

func TestParseWhoisResponseSG_NotFound(t *testing.T) {
	response := "% Domain not registered\r\n"
	_, err := ParseWhoisResponseSG(response, "notfound.sg")
	if !errors.Is(err, utils.ErrDomainNotFound) {
		t.Errorf("expected ErrDomainNotFound, got %v", err)
	}
}

func TestParseWhoisResponseJP(t *testing.T) {
	response := `[Domain Name] EXAMPLE.JP
[Registrant] Example JP Corp
[Name Server] ns1.example.jp
[Name Server] ns2.example.jp
[登録年月日] 2010/03/01
[有効期限] 2026/03/01
[状態] Active
[最終更新] 2025/01/01 09:00:00 (JST)`

	domain := "example.jp"
	info, err := ParseWhoisResponseJP(response, domain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.LdhName != "example.jp" {
		t.Errorf("LdhName: got %q, want example.jp (lowercased from response)", info.LdhName)
	}
	if info.Registrar != "Example JP Corp" {
		t.Errorf("Registrar: got %q", info.Registrar)
	}
	if info.RegistrationDate != "2010-03-01" {
		t.Errorf("RegistrationDate: got %q", info.RegistrationDate)
	}
	if info.ExpirationDate != "2026-03-01" {
		t.Errorf("ExpirationDate: got %q", info.ExpirationDate)
	}
	// 2025/01/01 09:00:00 JST = 2025-01-01T00:00:00Z
	if info.LastChangedDate != "2025-01-01T00:00:00Z" {
		t.Errorf("LastChangedDate: got %q, want 2025-01-01T00:00:00Z", info.LastChangedDate)
	}
	if len(info.Nameservers) != 2 {
		t.Errorf("Nameservers count: got %d, want 2", len(info.Nameservers))
	}
	if info.SecureDNS == nil || info.SecureDNS.DelegationSigned {
		t.Errorf("SecureDNS: got %+v, want unsigned", info.SecureDNS)
	}
}

func TestParseWhoisResponseJP_CoJp(t *testing.T) {
	response := `a. [ドメイン名] EXAMPLE.CO.JP
g. [Organization] Example CO JP Corp
p. [ネームサーバ] ns1.example.co.jp
[登録年月日] 2010/03/01
[状態] Connected (2026/03/01)
[最終更新] 2025/01/01 09:00:00 (JST)`

	domain := "example.co.jp"
	info, err := ParseWhoisResponseJP(response, domain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Registrar != "Example CO JP Corp" {
		t.Errorf("Registrar: got %q", info.Registrar)
	}
	if info.ExpirationDate != "2026-03-01" {
		t.Errorf("ExpirationDate from status: got %q", info.ExpirationDate)
	}
}

func TestParseWhoisResponseJP_NotFound(t *testing.T) {
	response := `No match!!`
	_, err := ParseWhoisResponseJP(response, "notfound.jp")
	if !errors.Is(err, utils.ErrDomainNotFound) {
		t.Errorf("expected ErrDomainNotFound, got %v", err)
	}
}

func TestParseWhoisResponseEU(t *testing.T) {
	// 真实 whois.eu 响应节选（前缀的 % 法律声明省略）
	response := `% WHOIS eurid.eu
Domain: eurid.eu
Script: LATIN

Registrant:
        NOT DISCLOSED!
        Visit www.eurid.eu for the web-based WHOIS.

Technical:
        Organisation: EURid vzw
        Language: en
        Email: tech@eurid.eu

Registrar:
        Name: EURid vzw
        Website: https://www.eurid.eu

Name servers:
        ns3.eurid.eu (2001:67c:9c:3937::253)
        ns3.eurid.eu (185.36.4.253)
        nsp.netnod.se
        ns1.eurid.eu (2001:67c:9c:3937::252)
        ns1.eurid.eu (185.36.4.252)

Keys:
        flags:KSK protocol:3 algorithm:RSA_SHA256 pubKey:AwEAAcOQldGtC33GLx8s335UscKMPlWjDXCqbhR2QyAYcfS4CZS6YHg3A1Zz

Please visit www.eurid.eu for more info.
`

	domain := "eurid.eu"
	expected := model.DomainInfo{
		ObjectClassName: model.ObjectClassDomain,
		LdhName:         domain,
		Registrar:       "EURid vzw",
		Nameservers:     []string{"ns3.eurid.eu", "nsp.netnod.se", "ns1.eurid.eu"},
		SecureDNS:       &model.SecureDNS{DelegationSigned: true},
	}

	domainInfo, err := ParseWhoisResponseEU(response, domain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := time.Parse(time.RFC3339, domainInfo.LastUpdateOfRdapDb); err != nil {
		t.Errorf("LastUpdateOfRdapDb is not a valid RFC3339 timestamp: %v", domainInfo.LastUpdateOfRdapDb)
	}
	domainInfo.LastUpdateOfRdapDb = ""
	if !reflect.DeepEqual(domainInfo, expected) {
		t.Errorf("expected %+v, got %+v", expected, domainInfo)
	}
}

func TestParseWhoisResponseEU_Unsigned(t *testing.T) {
	response := `% WHOIS example.eu
Domain: example.eu
Script: LATIN

Registrar:
        Name: Example Registrar BV
        Website: https://registrar.example

Name servers:
        ns1.example.net
        ns2.example.net

Please visit www.eurid.eu for more info.
`

	domainInfo, err := ParseWhoisResponseEU(response, "example.eu")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if domainInfo.SecureDNS == nil || domainInfo.SecureDNS.DelegationSigned {
		t.Errorf("expected unsigned secureDNS, got %+v", domainInfo.SecureDNS)
	}
	if len(domainInfo.Nameservers) != 2 {
		t.Errorf("nameservers: %+v", domainInfo.Nameservers)
	}
}

func TestParseWhoisResponseEU_NotFound(t *testing.T) {
	response := `% WHOIS zzz-notexist.eu
Domain: zzz-notexist.eu
Script: LATIN
Status: AVAILABLE
`

	_, err := ParseWhoisResponseEU(response, "zzz-notexist.eu")
	if !errors.Is(err, utils.ErrDomainNotFound) {
		t.Errorf("expected ErrDomainNotFound, got %v", err)
	}
}

func TestParseWhoisResponseKR(t *testing.T) {
	// 真实 whois.kr 响应节选（韩文段在前、英文段在后）
	response := `query : naver.kr


# KOREAN(UTF8)

도메인이름                  : naver.kr
등록일                      : 2007. 02. 28.
최근 정보 변경일            : 2018. 02. 28.
사용 종료일                 : 2027. 02. 28.
등록대행자                  : (주)가비아(http://www.gabia.co.kr)
DNSSEC                      : 미서명

1차 네임서버 정보
   호스트이름               : ns1.naver.com

2차 네임서버 정보
   호스트이름               : ns2.naver.com


# ENGLISH

Domain Name                 : naver.kr
Registrant                  : NAVER Corp.
Registrant Address          : 6 Buljung-ro, Bundang-gu, Seongnam-si, Gyeonggi-do, 463-867, Korea, &nbsp;
Registrant Zip Code         : 463867
Administrative Contact(AC)  : NAVER Corp.
AC E-Mail                   : dl_ssl@navercorp.com
AC Phone Number             : +82.28293528
Registered Date             : 2007. 02. 28.
Last Updated Date           : 2018. 02. 28.
Expiration Date             : 2027. 02. 28.
Publishes                   : Y
Authorized Agency           : Gabia, Inc.(http://www.gabia.co.kr)
DNSSEC                      : unsigned

Primary Name Server
   Host Name                : ns1.naver.com

Secondary Name Server
   Host Name                : ns2.naver.com


- KISA/KRNIC WHOIS Service -
`

	domain := "naver.kr"
	expected := model.DomainInfo{
		ObjectClassName:  model.ObjectClassDomain,
		LdhName:          domain,
		RegistrationDate: "2007-02-28",
		LastChangedDate:  "2018-02-28",
		ExpirationDate:   "2027-02-28",
		Registrar:        "Gabia, Inc.",
		Nameservers:      []string{"ns1.naver.com", "ns2.naver.com"},
		SecureDNS:        &model.SecureDNS{DelegationSigned: false},
	}

	domainInfo, err := ParseWhoisResponseKR(response, domain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := time.Parse(time.RFC3339, domainInfo.LastUpdateOfRdapDb); err != nil {
		t.Errorf("LastUpdateOfRdapDb is not a valid RFC3339 timestamp: %v", domainInfo.LastUpdateOfRdapDb)
	}
	domainInfo.LastUpdateOfRdapDb = ""
	if !reflect.DeepEqual(domainInfo, expected) {
		t.Errorf("expected %+v, got %+v", expected, domainInfo)
	}
}

func TestParseWhoisResponseKR_NotFound(t *testing.T) {
	response := `query : zzz-notexist.kr


# KOREAN(UTF8)

상기 도메인이름은 등록되어 있지 않습니다.


# ENGLISH

The requested domain was not found in the Registry or Registrar’s WHOIS Server.


- KISA/KRNIC WHOIS Service -
`

	_, err := ParseWhoisResponseKR(response, "zzz-notexist.kr")
	if !errors.Is(err, utils.ErrDomainNotFound) {
		t.Errorf("expected ErrDomainNotFound, got %v", err)
	}
}

func TestParseWhoisResponseKR_Restricted(t *testing.T) {
	// 注册资格受限的域名（如 nic.kr）不返回任何字段
	response := `query : nic.kr


# KOREAN(UTF8)

상기 도메인이름은 도메인이름의 안정적 관리와 공공의 이익 등을 위하여 
등록자격이 제한된 도메인이름입니다.


# ENGLISH

This request domain name is restricted to specifically qualified registrants for stable management of domain names and public interest.


- KISA/KRNIC WHOIS Service -
`

	_, err := ParseWhoisResponseKR(response, "nic.kr")
	if !errors.Is(err, utils.ErrDomainNotFound) {
		t.Errorf("expected ErrDomainNotFound, got %v", err)
	}
}

func TestParseDSRecord(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		want   model.DSData
		wantOK bool
	}{
		{
			name:   "single-line DS record",
			in:     "12345 8 2 49FD46E6C4B45C55D4AC",
			want:   model.DSData{KeyTag: 12345, Algorithm: 8, DigestType: 2, Digest: "49FD46E6C4B45C55D4AC"},
			wantOK: true,
		},
		{
			name:   "digest split across fields is concatenated",
			in:     "7240 8 2 E147A85589E24FE0 DBB5980C73501B5D",
			want:   model.DSData{KeyTag: 7240, Algorithm: 8, DigestType: 2, Digest: "E147A85589E24FE0DBB5980C73501B5D"},
			wantOK: true,
		},
		{
			name:   "too few fields",
			in:     "12345 8 2",
			wantOK: false,
		},
		{
			name:   "non-numeric keyTag",
			in:     "abc 8 2 DEADBEEF",
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseDSRecord(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("ok: got %v, want %v", ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Errorf("DSData: got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseWhoisResponseSO_DSData(t *testing.T) {
	// A signed .so domain carries a single-line DS record in "DNSSEC DS Data".
	response := `Registrar: Example SO Registrar
Domain Status: active
Registrar IANA ID: 1234
Creation Date: 2010-03-01T00:00:00Z
Registry Expiry Date: 2026-03-01T00:00:00Z
Name Server: ns1.example.so
DNSSEC: signedDelegation
DNSSEC DS Data: 12345 8 2 49FD46E6C4B45C55D4AC1BFB1B2C3D4E5F60718293A4B5C6`

	info, err := ParseWhoisResponseSO(response, "example.so")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.SecureDNS == nil || !info.SecureDNS.DelegationSigned {
		t.Fatalf("SecureDNS: got %+v, want signed", info.SecureDNS)
	}
	want := []model.DSData{{KeyTag: 12345, Algorithm: 8, DigestType: 2, Digest: "49FD46E6C4B45C55D4AC1BFB1B2C3D4E5F60718293A4B5C6"}}
	if !reflect.DeepEqual(info.SecureDNS.DSData, want) {
		t.Errorf("DSData: got %+v, want %+v", info.SecureDNS.DSData, want)
	}
}

func TestParseWhoisResponseJP_Signed(t *testing.T) {
	// Excerpt of the real default (Japanese-label) JPRS response for a
	// DNSSEC-signed domain. [Signing Key] carries a DS record
	// ("keyTag algorithm digestType digest") with the digest wrapped in
	// parentheses across continuation lines.
	response := `Domain Information: [ドメイン情報]
[Domain Name]                   JPRS.JP

[登録者名]                      株式会社日本レジストリサービス
[Registrant]                    Japan Registry Services Co.,Ltd.

[Name Server]                   ns1.jprs.jp
[Name Server]                   ns2.jprs.jp
[Signing Key]                   7240 8 2 (
                                E147A85589E24FE0DBB5980C73501B5D
                                D656BE5550714F150BE574AE8777B77D )

[登録年月日]                    2001/02/02
[有効期限]                      2027/02/28
[状態]                          Active
[最終更新]                      2026/03/01 01:05:03 (JST)`

	info, err := ParseWhoisResponseJP(response, "jprs.jp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.SecureDNS == nil || !info.SecureDNS.DelegationSigned {
		t.Fatalf("SecureDNS: got %+v, want signed", info.SecureDNS)
	}
	want := []model.DSData{{
		KeyTag:     7240,
		Algorithm:  8,
		DigestType: 2,
		Digest:     "E147A85589E24FE0DBB5980C73501B5DD656BE5550714F150BE574AE8777B77D",
	}}
	if !reflect.DeepEqual(info.SecureDNS.DSData, want) {
		t.Errorf("DSData: got %+v, want %+v", info.SecureDNS.DSData, want)
	}
}
