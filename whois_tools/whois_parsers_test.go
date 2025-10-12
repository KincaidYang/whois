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
	if domainInfo.DomainName != domain {
		t.Errorf("Expected domain name %s, got %s", domain, domainInfo.DomainName)
	}

	// 验证注册商
	expectedRegistrar := "TLD Registrar Solutions Ltd"
	if domainInfo.Registrar != expectedRegistrar {
		t.Errorf("Expected registrar %s, got %s", expectedRegistrar, domainInfo.Registrar)
	}

	// 验证创建日期
	expectedCreationDate := "2000-11-20T01:00:00.0Z"
	if domainInfo.CreationDate != expectedCreationDate {
		t.Errorf("Expected creation date %s, got %s", expectedCreationDate, domainInfo.CreationDate)
	}

	// 验证过期日期
	expectedExpiryDate := "2026-11-20T23:59:59.0Z"
	if domainInfo.RegistryExpiryDate != expectedExpiryDate {
		t.Errorf("Expected expiry date %s, got %s", expectedExpiryDate, domainInfo.RegistryExpiryDate)
	}

	// 验证更新日期
	expectedUpdatedDate := "2016-10-17T04:13:14.0Z"
	if domainInfo.UpdatedDate != expectedUpdatedDate {
		t.Errorf("Expected updated date %s, got %s", expectedUpdatedDate, domainInfo.UpdatedDate)
	}

	// 验证名称服务器
	if len(domainInfo.NameServer) != 6 {
		t.Errorf("Expected 6 name servers, got %d", len(domainInfo.NameServer))
	}
	expectedNameServers := []string{
		"NS0.CENTRALNIC-DNS.COM",
		"NS1.CENTRALNIC-DNS.COM",
		"NS2.CENTRALNIC-DNS.COM",
		"NS3.CENTRALNIC-DNS.COM",
		"NS4.CENTRALNIC-DNS.COM",
		"NS5.CENTRALNIC-DNS.COM",
	}
	for i, expectedNS := range expectedNameServers {
		if i < len(domainInfo.NameServer) && domainInfo.NameServer[i] != expectedNS {
			t.Errorf("Expected name server[%d] %s, got %s", i, expectedNS, domainInfo.NameServer[i])
		}
	}

	// 验证 DNSSEC
	expectedDNSSEC := "unsigned"
	if domainInfo.DNSSec != expectedDNSSEC {
		t.Errorf("Expected DNSSEC %s, got %s", expectedDNSSEC, domainInfo.DNSSec)
	}

	// 验证域名状态
	if len(domainInfo.DomainStatus) != 5 {
		t.Errorf("Expected 5 domain statuses, got %d", len(domainInfo.DomainStatus))
	}
	expectedStatuses := []string{
		"serverTransferProhibited https://icann.org/epp#serverTransferProhibited",
		"serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited",
		"serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited",
		"serverRenewProhibited https://icann.org/epp#serverRenewProhibited",
		"clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
	}
	for i, expectedStatus := range expectedStatuses {
		if i < len(domainInfo.DomainStatus) && domainInfo.DomainStatus[i] != expectedStatus {
			t.Errorf("Expected domain status[%d] %s, got %s", i, expectedStatus, domainInfo.DomainStatus[i])
		}
	}

	// 验证数据库最后更新时间
	expectedDBUpdate := "2025-10-12T05:44:20.0Z"
	if domainInfo.LastUpdateOfRDAPDB != expectedDBUpdate {
		t.Errorf("Expected last update of DB %s, got %s", expectedDBUpdate, domainInfo.LastUpdateOfRDAPDB)
	}

	// 验证 Registrar IANA ID 为空（因为原始数据中是空的）
	if domainInfo.RegistrarIANAID != "" {
		t.Errorf("Expected empty Registrar IANA ID, got %s", domainInfo.RegistrarIANAID)
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
