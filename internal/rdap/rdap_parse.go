package rdap

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/KincaidYang/whois/internal/model"
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
	UnicodeName string           `json:"unicodeName"`
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
func ParseRDAPResponseforDomain(response string) (model.DomainInfo, error) {
	var rdap rdapDomainResponse
	if err := json.Unmarshal([]byte(response), &rdap); err != nil {
		return model.DomainInfo{}, err
	}

	info := model.DomainInfo{
		ObjectClassName: model.ObjectClassDomain,
		LdhName:         strings.ToLower(rdap.LdhName),
		UnicodeName:     rdap.UnicodeName,
		Status:          model.CleanStatus(rdap.Status),
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

	// Extract event dates, normalized to RFC 3339 UTC (unparseable values
	// are passed through unchanged).
	for _, event := range rdap.Events {
		date, _ := model.NormalizeDate(event.EventDate, time.UTC)
		switch event.EventAction {
		case "registration":
			info.RegistrationDate = date
		case "expiration":
			info.ExpirationDate = date
		case "last changed":
			info.LastChangedDate = date
		case "last update of RDAP database":
			info.LastUpdateOfRdapDb = date
		}
	}

	// Extract nameservers
	info.Nameservers = make([]string, 0, len(rdap.Nameservers))
	for _, ns := range rdap.Nameservers {
		info.Nameservers = append(info.Nameservers, strings.ToLower(ns.LdhName))
	}

	// Extract DNSSEC info
	info.SecureDNS = &model.SecureDNS{}
	if rdap.SecureDNS != nil && rdap.SecureDNS.DelegationSigned {
		info.SecureDNS.DelegationSigned = true
		for _, ds := range rdap.SecureDNS.DsData {
			info.SecureDNS.DSData = append(info.SecureDNS.DSData, model.DSData{
				KeyTag:     ds.KeyTag,
				Algorithm:  ds.Algorithm,
				DigestType: ds.DigestType,
				Digest:     ds.Digest,
			})
		}
	}

	return info, nil
}

// ParseRDAPResponseforIP parses the RDAP response for an IP address.
func ParseRDAPResponseforIP(response string) (model.IPInfo, error) {
	var rdap rdapIPResponse
	if err := json.Unmarshal([]byte(response), &rdap); err != nil {
		return model.IPInfo{}, err
	}

	info := model.IPInfo{
		ObjectClassName: model.ObjectClassIPNetwork,
		Handle:          rdap.Handle,
		StartAddress:    rdap.StartAddress,
		EndAddress:      rdap.EndAddress,
		Name:            rdap.Name,
		Country:         rdap.Country,
		Status:          model.CleanStatus(rdap.Status),
	}

	if rdap.Type != nil {
		info.Type = *rdap.Type
	}

	for _, cidr := range rdap.Cidr0Cidrs {
		if cidr.V4Prefix != "" {
			info.CIDR = fmt.Sprintf("%s/%d", cidr.V4Prefix, int(cidr.Length))
		} else if cidr.V6Prefix != "" {
			info.CIDR = fmt.Sprintf("%s/%d", cidr.V6Prefix, int(cidr.Length))
		}
	}

	for _, event := range rdap.Events {
		date, _ := model.NormalizeDate(event.EventDate, time.UTC)
		switch event.EventAction {
		case "registration":
			info.RegistrationDate = date
		case "last changed":
			info.LastChangedDate = date
		}
	}

	for _, remark := range rdap.Remarks {
		info.Remarks = append(info.Remarks, model.Remark{
			Title:       remark.Title,
			Description: remark.Description,
		})
	}

	return info, nil
}

// ParseRDAPResponseforASN parses the RDAP response for an ASN.
func ParseRDAPResponseforASN(response string) (model.ASNInfo, error) {
	var rdap rdapASNResponse
	if err := json.Unmarshal([]byte(response), &rdap); err != nil {
		return model.ASNInfo{}, err
	}

	info := model.ASNInfo{
		ObjectClassName: model.ObjectClassAutnum,
		Handle:          rdap.Handle,
		Name:            rdap.Name,
		Status:          model.CleanStatus(rdap.Status),
	}

	for _, event := range rdap.Events {
		date, _ := model.NormalizeDate(event.EventDate, time.UTC)
		switch event.EventAction {
		case "registration":
			info.RegistrationDate = date
		case "last changed":
			info.LastChangedDate = date
		}
	}

	for _, remark := range rdap.Remarks {
		info.Remarks = append(info.Remarks, model.Remark{
			Title:       remark.Title,
			Description: remark.Description,
		})
	}

	return info, nil
}
