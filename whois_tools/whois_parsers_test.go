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

	// Ignore LastUpdateOfRDAPDB field for comparison
	domainInfo.LastUpdateOfRDAPDB = ""
	if !reflect.DeepEqual(domainInfo, expected) {
		t.Errorf("expected %+v, got %+v", expected, domainInfo)
	}

	// Validate that LastUpdateOfRDAPDB is a valid RFC3339 timestamp
	if _, err := time.Parse(time.RFC3339, domainInfo.LastUpdateOfRDAPDB); err != nil {
		t.Errorf("LastUpdateOfRDAPDB is not a valid RFC3339 timestamp: %v", domainInfo.LastUpdateOfRDAPDB)
	}
}
