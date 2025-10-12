package whois_tools

import (
	"reflect"
	"testing"
	"time"

	"github.com/KincaidYang/whois/rdap_tools/structs"
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
	expected := structs.DomainInfo{
		DomainName:         domain,
		CreationDate:       "2025-03-01T04:00:00Z", // Converted to UTC
		RegistryExpiryDate: "2026-03-01T04:00:00Z",
		NameServer:         []string{"ns1.example.com", "ns2.example.com"},
		DNSSec:             "unsigned",
		Registrar:          "Example Registrar",
		DomainStatus:       []string{"active"},
	}

	domainInfo, err := ParseWhoisResponseCN(response, domain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Validate that LastUpdateOfRDAPDB is a valid RFC3339 timestamp
	if _, err := time.Parse(time.RFC3339, domainInfo.LastUpdateOfRDAPDB); err != nil {
		t.Errorf("LastUpdateOfRDAPDB is not a valid RFC3339 timestamp: %v", domainInfo.LastUpdateOfRDAPDB)
	}

	// Ignore LastUpdateOfRDAPDB field for comparison
	domainInfo.LastUpdateOfRDAPDB = ""
	if !reflect.DeepEqual(domainInfo, expected) {
		t.Errorf("expected %+v, got %+v", expected, domainInfo)
	}
}

func TestParseWhoisResponseLA(t *testing.T) {
	// 测试用的原始 Whois 响应数据
	response := `Domain Name: ZZ.LA
Registry Domain ID: D468776-LANIC
Registrar WHOIS Server:
Registrar URL:
Updated Date: 2024-11-08T09:03:35.0Z
Creation Date: 2006-11-16T01:00:00.0Z
Registry Expiry Date: 2025-11-16T23:59:59.0Z
Registrar: 1API GmbH
Registrar IANA ID:
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registrant Email: https://whois.nic.la/contact/zz.la/registrant
Admin Email: https://whois.nic.la/contact/zz.la/admin
Tech Email: https://whois.nic.la/contact/zz.la/tech
Name Server: F1G1NS1.DNSPOD.NET
Name Server: F1G1NS2.DNSPOD.NET
DNSSEC: unsigned
Billing Email: https://whois.nic.la/contact/zz.la/billing
Registrar Abuse Contact Email: abuse@centralnic.com
Registrar Abuse Contact Phone: +49.68416984
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of WHOIS database: 2025-10-12T04:26:45.0Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

This whois service is provided by LANIC and only contains
information pertaining to Internet domain names registered by our
our customers. By using this service you are agreeing (1) not to use any
information presented here for any purpose other than determining
ownership of domain names, (2) not to store or reproduce this data in
any way, (3) not to use any high-volume, automated, electronic processes
to obtain data from this service. Abuse of this service is monitored and
actions in contravention of these terms will result in being permanently
blacklisted. All data is (c) LANIC http://www.lanic.gov.la/

Access to the whois service is rate limited. For more information, please
see https://registrar-console.lanic.la/pub/whois_guidance.`

	domain := "zz.la"
	domainInfo, err := ParseWhoisResponseLA(response, domain)

	if err != nil {
		t.Fatalf("ParseWhoisResponseLA returned an error: %v", err)
	}

	// 验证域名
	if domainInfo.DomainName != domain {
		t.Errorf("Expected domain name %s, got %s", domain, domainInfo.DomainName)
	}

	// 验证注册商
	expectedRegistrar := "1API GmbH"
	if domainInfo.Registrar != expectedRegistrar {
		t.Errorf("Expected registrar %s, got %s", expectedRegistrar, domainInfo.Registrar)
	}

	// 验证创建日期
	expectedCreationDate := "2006-11-16T01:00:00.0Z"
	if domainInfo.CreationDate != expectedCreationDate {
		t.Errorf("Expected creation date %s, got %s", expectedCreationDate, domainInfo.CreationDate)
	}

	// 验证过期日期
	expectedExpiryDate := "2025-11-16T23:59:59.0Z"
	if domainInfo.RegistryExpiryDate != expectedExpiryDate {
		t.Errorf("Expected expiry date %s, got %s", expectedExpiryDate, domainInfo.RegistryExpiryDate)
	}

	// 验证更新日期
	expectedUpdatedDate := "2024-11-08T09:03:35.0Z"
	if domainInfo.UpdatedDate != expectedUpdatedDate {
		t.Errorf("Expected updated date %s, got %s", expectedUpdatedDate, domainInfo.UpdatedDate)
	}

	// 验证名称服务器
	if len(domainInfo.NameServer) != 2 {
		t.Errorf("Expected 2 name servers, got %d", len(domainInfo.NameServer))
	}
	expectedNS1 := "F1G1NS1.DNSPOD.NET"
	expectedNS2 := "F1G1NS2.DNSPOD.NET"
	if len(domainInfo.NameServer) >= 1 && domainInfo.NameServer[0] != expectedNS1 {
		t.Errorf("Expected first name server %s, got %s", expectedNS1, domainInfo.NameServer[0])
	}
	if len(domainInfo.NameServer) >= 2 && domainInfo.NameServer[1] != expectedNS2 {
		t.Errorf("Expected second name server %s, got %s", expectedNS2, domainInfo.NameServer[1])
	}

	// 验证 DNSSEC
	expectedDNSSEC := "unsigned"
	if domainInfo.DNSSec != expectedDNSSEC {
		t.Errorf("Expected DNSSEC %s, got %s", expectedDNSSEC, domainInfo.DNSSec)
	}

	// 验证域名状态
	if len(domainInfo.DomainStatus) != 1 {
		t.Errorf("Expected 1 domain status, got %d", len(domainInfo.DomainStatus))
	}
	expectedStatus := "clientTransferProhibited https://icann.org/epp#clientTransferProhibited"
	if len(domainInfo.DomainStatus) >= 1 && domainInfo.DomainStatus[0] != expectedStatus {
		t.Errorf("Expected domain status %s, got %s", expectedStatus, domainInfo.DomainStatus[0])
	}

	// 验证数据库最后更新时间
	expectedDBUpdate := "2025-10-12T04:26:45.0Z"
	if domainInfo.LastUpdateOfRDAPDB != expectedDBUpdate {
		t.Errorf("Expected last update of DB %s, got %s", expectedDBUpdate, domainInfo.LastUpdateOfRDAPDB)
	}
}

func TestParseWhoisResponseLA_DomainNotFound(t *testing.T) {
	// 测试域名不存在的情况 - 缺少必要字段
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

	expectedError := "domain not found"
	if err.Error() != expectedError {
		t.Errorf("Expected error message '%s', got '%s'", expectedError, err.Error())
	}
}
