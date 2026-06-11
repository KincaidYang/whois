package rdap

import (
	"reflect"
	"testing"

	"github.com/KincaidYang/whois/internal/model"
)

// TestParseRDAPDomainRegistrar covers the common gTLD shape (modeled on
// Verisign .com): top-level registrar entity with an IANA Registrar ID.
func TestParseRDAPDomainRegistrar(t *testing.T) {
	response := `{
		"objectClassName": "domain",
		"ldhName": "EXAMPLE.COM",
		"status": ["client delete prohibited"],
		"entities": [{
			"objectClassName": "entity",
			"roles": ["registrar"],
			"publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}],
			"vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]]
		}],
		"events": [
			{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
			{"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"}
		],
		"nameservers": [
			{"ldhName": "A.IANA-SERVERS.NET"},
			{"ldhName": "B.IANA-SERVERS.NET"}
		],
		"secureDNS": {
			"delegationSigned": true,
			"dsData": [{"keyTag": 370, "algorithm": 13, "digestType": 2, "digest": "BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C"}]
		}
	}`

	info, err := ParseRDAPResponseforDomain(response)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := model.DomainInfo{
		ObjectClassName:  model.ObjectClassDomain,
		LdhName:          "example.com",
		Registrar:        "RESERVED-Internet Assigned Numbers Authority",
		RegistrarIANAID:  "376",
		Status:           []string{"client delete prohibited"},
		RegistrationDate: "1995-08-14T04:00:00Z",
		ExpirationDate:   "2026-08-13T04:00:00Z",
		Nameservers:      []string{"a.iana-servers.net", "b.iana-servers.net"},
		SecureDNS: &model.SecureDNS{
			DelegationSigned: true,
			DSData: []model.DSData{{
				KeyTag: 370, Algorithm: 13, DigestType: 2,
				Digest: "BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C",
			}},
		},
	}
	if !reflect.DeepEqual(info, expected) {
		t.Errorf("expected %+v, got %+v", expected, info)
	}
}

// TestParseRDAPDomainNonIANAPublicId verifies a public ID of another type
// (Nominet's "Registry Identifier: NOMINET") is not mistaken for the IANA
// registrar ID, and trailing-dot nameservers are normalized.
func TestParseRDAPDomainNonIANAPublicId(t *testing.T) {
	response := `{
		"ldhName": "nominet.uk",
		"entities": [{
			"roles": ["registrar"],
			"publicIds": [{"type": "Registry Identifier", "identifier": "NOMINET"}],
			"vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Nominet UK"]]]
		}],
		"nameservers": [
			{"ldhName": "dns1.nominetdns.uk."},
			{"ldhName": "dns2.nominetdns.uk."}
		]
	}`

	info, err := ParseRDAPResponseforDomain(response)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Registrar != "Nominet UK" {
		t.Errorf("registrar: %q", info.Registrar)
	}
	if info.RegistrarIANAID != "" {
		t.Errorf("registrarIanaId should be empty for non-IANA public IDs, got %q", info.RegistrarIANAID)
	}
	if !reflect.DeepEqual(info.Nameservers, []string{"dns1.nominetdns.uk", "dns2.nominetdns.uk"}) {
		t.Errorf("nameservers not normalized: %+v", info.Nameservers)
	}
}

// TestParseRDAPDomainKeyDataOnly verifies a DENIC-style secureDNS object —
// keyData with no delegationSigned boolean — is reported as signed and the
// key material is surfaced.
func TestParseRDAPDomainKeyDataOnly(t *testing.T) {
	response := `{
		"ldhName": "denic.de",
		"status": ["active"],
		"nameservers": [{"ldhName": "ns1.denic.de."}],
		"secureDNS": {
			"keyData": [{"algorithm": 8, "flags": 257, "protocol": 3, "publicKey": "AwEAAZ4e0YL"}]
		}
	}`

	info, err := ParseRDAPResponseforDomain(response)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.SecureDNS.DelegationSigned {
		t.Error("keyData-only secureDNS should report delegationSigned=true")
	}
	expected := []model.KeyData{{Flags: 257, Protocol: 3, Algorithm: 8, PublicKey: "AwEAAZ4e0YL"}}
	if !reflect.DeepEqual(info.SecureDNS.KeyData, expected) {
		t.Errorf("keyData: %+v", info.SecureDNS.KeyData)
	}
}

// TestParseRDAPDomainNestedRegistrar verifies the registrar entity is found
// when nested inside another entity.
func TestParseRDAPDomainNestedRegistrar(t *testing.T) {
	response := `{
		"ldhName": "example.org",
		"entities": [{
			"roles": ["registrant"],
			"entities": [{
				"roles": ["registrar"],
				"publicIds": [{"type": "IANA Registrar ID", "identifier": "292"}],
				"vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "MarkMonitor Inc."]]]
			}]
		}]
	}`

	info, err := ParseRDAPResponseforDomain(response)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Registrar != "MarkMonitor Inc." || info.RegistrarIANAID != "292" {
		t.Errorf("nested registrar not found: registrar=%q ianaId=%q", info.Registrar, info.RegistrarIANAID)
	}
}

// TestParseRDAPDomainNoRegistrar verifies registry-operated TLDs (.br) that
// carry no registrar entity parse cleanly with the field absent.
func TestParseRDAPDomainNoRegistrar(t *testing.T) {
	response := `{
		"ldhName": "registro.br",
		"entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Owner"]]]}],
		"secureDNS": {"delegationSigned": true, "dsData": [{"keyTag": 1, "algorithm": 13, "digestType": 2, "digest": "AB"}]}
	}`

	info, err := ParseRDAPResponseforDomain(response)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Registrar != "" || info.RegistrarIANAID != "" {
		t.Errorf("expected no registrar, got %q / %q", info.Registrar, info.RegistrarIANAID)
	}
	if !info.SecureDNS.DelegationSigned || len(info.SecureDNS.DSData) != 1 {
		t.Errorf("secureDNS: %+v", info.SecureDNS)
	}
}

// TestParseRDAPDomainDsDataWithoutBoolean verifies dsData is kept (and the
// delegation reported signed) when the registry omits delegationSigned.
func TestParseRDAPDomainDsDataWithoutBoolean(t *testing.T) {
	response := `{
		"ldhName": "example.fr",
		"secureDNS": {"dsData": [{"keyTag": 5, "algorithm": 8, "digestType": 2, "digest": "CD"}]}
	}`

	info, err := ParseRDAPResponseforDomain(response)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.SecureDNS.DelegationSigned || len(info.SecureDNS.DSData) != 1 {
		t.Errorf("secureDNS: %+v", info.SecureDNS)
	}
}
