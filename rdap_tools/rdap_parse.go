package rdap_tools

import (
	"encoding/json"
	"fmt"

	"github.com/KincaidYang/whois/rdap_tools/structs"
)

// Internal structs for safe RDAP JSON deserialization.
// Using typed structs instead of map[string]interface{} eliminates panic risk
// from unchecked type assertions on unexpected server responses.

type rdapEvent struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

type rdapPublicId struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

type rdapEntity struct {
	Roles      []string          `json:"roles"`
	VcardArray []json.RawMessage `json:"vcardArray"`
	PublicIds  []rdapPublicId    `json:"publicIds"`
}

type rdapNameserver struct {
	LdhName string `json:"ldhName"`
}

type rdapDsData struct {
	KeyTag     int    `json:"keyTag"`
	Algorithm  int    `json:"algorithm"`
	DigestType int    `json:"digestType"`
	Digest     string `json:"digest"`
}

type rdapSecureDNS struct {
	DelegationSigned bool         `json:"delegationSigned"`
	DsData           []rdapDsData `json:"dsData"`
}

type rdapDomainResponse struct {
	LdhName     string           `json:"ldhName"`
	Status      []string         `json:"status"`
	Entities    []rdapEntity     `json:"entities"`
	Events      []rdapEvent      `json:"events"`
	Nameservers []rdapNameserver `json:"nameservers"`
	SecureDNS   *rdapSecureDNS   `json:"secureDNS"`
}

type rdapCIDR struct {
	V4Prefix string  `json:"v4prefix"`
	V6Prefix string  `json:"v6prefix"`
	Length   float64 `json:"length"`
}

type rdapRemark struct {
	Title       string   `json:"title"`
	Description []string `json:"description"`
}

type rdapIPResponse struct {
	Handle       string       `json:"handle"`
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	Name         string       `json:"name"`
	Cidr0Cidrs   []rdapCIDR   `json:"cidr0_cidrs"`
	Type         *string      `json:"type"`
	Country      string       `json:"country"`
	Status       []string     `json:"status"`
	Events       []rdapEvent  `json:"events"`
	Remarks      []rdapRemark `json:"remarks"`
}

type rdapASNResponse struct {
	Handle  string       `json:"handle"`
	Name    string       `json:"name"`
	Status  []string     `json:"status"`
	Events  []rdapEvent  `json:"events"`
	Remarks []rdapRemark `json:"remarks"`
}

// extractRegistrarName extracts the "fn" (full name) property from a vCard array.
// The vCard format per RFC 7095 is: ["vcard", [["fn", {}, "text", "Name"], ...]]
func extractRegistrarName(vcardArray []json.RawMessage) string {
	if len(vcardArray) < 2 {
		return ""
	}
	var properties []json.RawMessage
	if err := json.Unmarshal(vcardArray[1], &properties); err != nil {
		return ""
	}
	for _, prop := range properties {
		var fields []json.RawMessage
		if err := json.Unmarshal(prop, &fields); err != nil {
			continue
		}
		if len(fields) < 4 {
			continue
		}
		var propName string
		if err := json.Unmarshal(fields[0], &propName); err != nil || propName != "fn" {
			continue
		}
		var value string
		if err := json.Unmarshal(fields[3], &value); err != nil {
			continue
		}
		return value
	}
	return ""
}

// ParseRDAPResponseforDomain parses the RDAP response for a domain and returns a DomainInfo structure.
func ParseRDAPResponseforDomain(response string) (structs.DomainInfo, error) {
	var rdap rdapDomainResponse
	if err := json.Unmarshal([]byte(response), &rdap); err != nil {
		return structs.DomainInfo{}, err
	}

	info := structs.DomainInfo{
		DomainName:   rdap.LdhName,
		DomainStatus: rdap.Status,
	}

	// Extract registrar info from entities
	for _, entity := range rdap.Entities {
		for _, role := range entity.Roles {
			if role == "registrar" {
				info.Registrar = extractRegistrarName(entity.VcardArray)
				if len(entity.PublicIds) > 0 {
					info.RegistrarIANAID = entity.PublicIds[0].Identifier
				}
				break
			}
		}
	}

	// Extract event dates
	for _, event := range rdap.Events {
		switch event.EventAction {
		case "registration":
			info.CreationDate = event.EventDate
		case "expiration":
			info.RegistryExpiryDate = event.EventDate
		case "last changed":
			info.UpdatedDate = event.EventDate
		case "last update of RDAP database":
			info.LastUpdateOfRDAPDB = event.EventDate
		}
	}

	// Extract nameservers
	info.NameServer = make([]string, 0, len(rdap.Nameservers))
	for _, ns := range rdap.Nameservers {
		info.NameServer = append(info.NameServer, ns.LdhName)
	}

	// Extract DNSSEC info
	info.DNSSec = "unsigned"
	if rdap.SecureDNS != nil && rdap.SecureDNS.DelegationSigned {
		info.DNSSec = "signedDelegation"
		for _, ds := range rdap.SecureDNS.DsData {
			info.DNSSecDSData = append(info.DNSSecDSData, fmt.Sprintf("%d %d %d %s",
				ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest))
		}
	}

	return info, nil
}

// ParseRDAPResponseforIP parses the RDAP response for an IP address.
func ParseRDAPResponseforIP(response string) (structs.IPInfo, error) {
	var rdap rdapIPResponse
	if err := json.Unmarshal([]byte(response), &rdap); err != nil {
		return structs.IPInfo{}, err
	}

	info := structs.IPInfo{
		IP:      rdap.Handle,
		NetName: rdap.Name,
		Country: rdap.Country,
		IPStatus: rdap.Status,
	}

	if rdap.StartAddress != "" {
		info.Range = rdap.StartAddress
		if rdap.EndAddress != "" {
			info.Range += " - " + rdap.EndAddress
		}
	}

	if rdap.Type != nil {
		info.Networktype = *rdap.Type
	} else {
		info.Networktype = "Unknown"
	}

	for _, cidr := range rdap.Cidr0Cidrs {
		if cidr.V4Prefix != "" {
			info.CIDR = fmt.Sprintf("%s/%d", cidr.V4Prefix, int(cidr.Length))
		} else if cidr.V6Prefix != "" {
			info.CIDR = fmt.Sprintf("%s/%d", cidr.V6Prefix, int(cidr.Length))
		}
	}

	for _, event := range rdap.Events {
		switch event.EventAction {
		case "registration":
			info.CreationDate = event.EventDate
		case "last changed":
			info.UpdatedDate = event.EventDate
		}
	}

	for _, remark := range rdap.Remarks {
		info.Remarks = append(info.Remarks, structs.Remark{
			Title:       remark.Title,
			Description: remark.Description,
		})
	}

	return info, nil
}

// ParseRDAPResponseforASN parses the RDAP response for an ASN.
func ParseRDAPResponseforASN(response string) (structs.ASNInfo, error) {
	var rdap rdapASNResponse
	if err := json.Unmarshal([]byte(response), &rdap); err != nil {
		return structs.ASNInfo{}, err
	}

	info := structs.ASNInfo{
		ASN:      rdap.Handle,
		ASName:   rdap.Name,
		ASStatus: rdap.Status,
	}

	for _, event := range rdap.Events {
		switch event.EventAction {
		case "registration":
			info.CreationDate = event.EventDate
		case "last changed":
			info.UpdatedDate = event.EventDate
		}
	}

	for _, remark := range rdap.Remarks {
		info.Remarks = append(info.Remarks, structs.Remark{
			Title:       remark.Title,
			Description: remark.Description,
		})
	}

	return info, nil
}
