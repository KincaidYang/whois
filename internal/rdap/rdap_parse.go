package rdap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/KincaidYang/whois/internal/model"
	"github.com/KincaidYang/whois/internal/utils"
	"golang.org/x/net/idna"
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
	Entities   []rdapEntity      `json:"entities"`
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

type rdapKeyData struct {
	Flags     int    `json:"flags"`
	Protocol  int    `json:"protocol"`
	Algorithm int    `json:"algorithm"`
	PublicKey string `json:"publicKey"`
}

type rdapSecureDNS struct {
	DelegationSigned bool          `json:"delegationSigned"`
	DsData           []rdapDsData  `json:"dsData"`
	KeyData          []rdapKeyData `json:"keyData"`
}

// rdapCommon holds the members every RDAP response may carry that decide
// whether it describes the requested object at all: its class, and the
// errorCode/title of an RFC 9083 error response (which some servers send
// with HTTP 200).
type rdapCommon struct {
	ObjectClassName string `json:"objectClassName"`
	ErrorCode       int    `json:"errorCode"`
	Title           string `json:"title"`
}

type rdapDomainResponse struct {
	rdapCommon
	LdhName     string           `json:"ldhName"`
	UnicodeName string           `json:"unicodeName"`
	Status      []string         `json:"status"`
	Entities    []rdapEntity     `json:"entities"`
	Events      []rdapEvent      `json:"events"`
	Nameservers []rdapNameserver `json:"nameservers"`
	SecureDNS   *rdapSecureDNS   `json:"secureDNS"`
}

// flexInt decodes a JSON number or a string holding one. The cidr0
// extension defines length as a number, but registro.br (reached through
// LACNIC redirects for Brazilian space) sends it as a string ("20"), which
// used to fail the whole response.
type flexInt int

func (n *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("cidr0 length %s: %w", b, err)
	}
	*n = flexInt(v)
	return nil
}

type rdapCIDR struct {
	V4Prefix string  `json:"v4prefix"`
	V6Prefix string  `json:"v6prefix"`
	Length   flexInt `json:"length"`
}

type rdapRemark struct {
	Title       string   `json:"title"`
	Description []string `json:"description"`
}

type rdapIPResponse struct {
	rdapCommon
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
	rdapCommon
	Handle      string       `json:"handle"`
	StartAutnum *uint32      `json:"startAutnum"`
	EndAutnum   *uint32      `json:"endAutnum"`
	Name        string       `json:"name"`
	Status      []string     `json:"status"`
	Events      []rdapEvent  `json:"events"`
	Remarks     []rdapRemark `json:"remarks"`
}

// ErrInvalidResponse marks an RDAP response that parsed as JSON but does not
// describe the requested object: null or an empty object, an error object, a
// different object class, or another resource than the one asked for. It is
// never cached, unlike a real result or a not-found.
var ErrInvalidResponse = errors.New("invalid RDAP response")

// checkCommon rejects error objects and objects of the wrong class. An error
// object with errorCode 404 is the server saying not-found in the body
// instead of the status line, and is reported as such. A missing
// objectClassName is tolerated: RFC 9083 requires it, but the identity checks
// that follow are what actually tie the response to the query.
func checkCommon(c rdapCommon, wantClass string) error {
	switch {
	case c.ErrorCode == http.StatusNotFound:
		return utils.ErrResourceNotFound
	case c.ErrorCode != 0:
		return fmt.Errorf("%w: error object %d %q", ErrInvalidResponse, c.ErrorCode, c.Title)
	case c.ObjectClassName != "" && !strings.EqualFold(c.ObjectClassName, wantClass):
		return fmt.Errorf("%w: objectClassName %q, want %q", ErrInvalidResponse, c.ObjectClassName, wantClass)
	}
	return nil
}

// normalizeDomainName reduces a domain name to the form names are compared
// in: lowercase A-labels, no trailing root dot.
func normalizeDomainName(name string) string {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if ascii, err := idna.ToASCII(name); err == nil {
		return ascii
	}
	return name
}

// addrRange returns the first and last address a query covers: an address
// covers itself, a prefix its whole block.
func addrRange(query string) (first, last netip.Addr, err error) {
	if !strings.Contains(query, "/") {
		a, err := netip.ParseAddr(query)
		return a.Unmap(), a.Unmap(), err
	}
	p, err := netip.ParsePrefix(query)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	p = p.Masked()
	first = p.Addr().Unmap()
	b := first.AsSlice()
	hostBits := first.BitLen() - p.Bits()
	for i := len(b) - 1; hostBits > 0; i-- {
		n := min(hostBits, 8)
		b[i] |= byte(1<<n - 1)
		hostBits -= n
	}
	last, _ = netip.AddrFromSlice(b)
	return first, last, nil
}

// handleASN reads the ASN out of an "AS<number>" handle (case-insensitive).
func handleASN(handle string) (uint32, bool) {
	if len(handle) < 3 || !strings.EqualFold(handle[:2], "AS") {
		return 0, false
	}
	n, err := strconv.ParseUint(handle[2:], 10, 32)
	return uint32(n), err == nil
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

// ParseRDAPResponseforDomain parses the RDAP response for domain (the name
// that was queried) into a DomainInfo. A response that is not a domain object
// for that very name is rejected with ErrInvalidResponse (or
// utils.ErrResourceNotFound for an in-body 404) rather than turned into an
// empty success.
func ParseRDAPResponseforDomain(response, domain string) (model.DomainInfo, error) {
	var rdap rdapDomainResponse
	if err := json.Unmarshal([]byte(response), &rdap); err != nil {
		return model.DomainInfo{}, err
	}
	if err := checkCommon(rdap.rdapCommon, model.ObjectClassDomain); err != nil {
		return model.DomainInfo{}, err
	}
	name := rdap.LdhName
	if name == "" {
		name = rdap.UnicodeName
	}
	if name == "" {
		return model.DomainInfo{}, fmt.Errorf("%w: no ldhName or unicodeName", ErrInvalidResponse)
	}
	if got, want := normalizeDomainName(name), normalizeDomainName(domain); got != want {
		return model.DomainInfo{}, fmt.Errorf("%w: describes %q, queried %q", ErrInvalidResponse, got, want)
	}

	info := model.DomainInfo{
		ObjectClassName: model.ObjectClassDomain,
		LdhName:         strings.ToLower(rdap.LdhName),
		UnicodeName:     rdap.UnicodeName,
		Status:          model.CleanStatus(rdap.Status),
	}

	// Extract registrar info from entities. The registrar entity is usually
	// top-level, but some registries nest it inside another entity, so the
	// search recurses. Only a public ID typed "IANA Registrar ID" is the IANA
	// ID — registries also attach other IDs (e.g. Nominet's
	// "Registry Identifier: NOMINET") that must not be mistaken for it.
	if registrar := findRegistrarEntity(rdap.Entities); registrar != nil {
		info.Registrar = extractRegistrarName(registrar.VcardArray)
		for _, id := range registrar.PublicIds {
			if strings.EqualFold(id.Type, "IANA Registrar ID") {
				info.RegistrarIANAID = id.Identifier
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

	// Extract nameservers. Some registries (DENIC, Nominet) return ldhName
	// as an FQDN with a trailing dot; strip it so hostnames are uniform
	// across registries.
	info.Nameservers = make([]string, 0, len(rdap.Nameservers))
	for _, ns := range rdap.Nameservers {
		info.Nameservers = append(info.Nameservers, strings.TrimSuffix(strings.ToLower(ns.LdhName), "."))
	}

	// Extract DNSSEC info. Published DS or DNSKEY records imply a signed
	// delegation even when the registry omits the delegationSigned boolean
	// (DENIC sends only keyData).
	info.SecureDNS = &model.SecureDNS{}
	if rdap.SecureDNS != nil {
		info.SecureDNS.DelegationSigned = rdap.SecureDNS.DelegationSigned ||
			len(rdap.SecureDNS.DsData) > 0 || len(rdap.SecureDNS.KeyData) > 0
		for _, ds := range rdap.SecureDNS.DsData {
			info.SecureDNS.DSData = append(info.SecureDNS.DSData, model.DSData{
				KeyTag:     ds.KeyTag,
				Algorithm:  ds.Algorithm,
				DigestType: ds.DigestType,
				Digest:     ds.Digest,
			})
		}
		for _, kd := range rdap.SecureDNS.KeyData {
			info.SecureDNS.KeyData = append(info.SecureDNS.KeyData, model.KeyData{
				Flags:     kd.Flags,
				Protocol:  kd.Protocol,
				Algorithm: kd.Algorithm,
				PublicKey: kd.PublicKey,
			})
		}
	}

	return info, nil
}

// findRegistrarEntity returns the first entity whose roles include
// "registrar", searching nested entities depth-first. Returns nil when the
// response has none (registry-operated TLDs like .br carry no registrar
// entity at all).
func findRegistrarEntity(entities []rdapEntity) *rdapEntity {
	for i := range entities {
		if slices.Contains(entities[i].Roles, "registrar") {
			return &entities[i]
		}
		if nested := findRegistrarEntity(entities[i].Entities); nested != nil {
			return nested
		}
	}
	return nil
}

// ParseRDAPResponseforIP parses the RDAP response for query (an address or
// a prefix). The network it describes must cover the whole query — a
// registry answers with the enclosing network, so containment, not equality,
// is what ties the two together.
func ParseRDAPResponseforIP(response, query string) (model.IPInfo, error) {
	var rdap rdapIPResponse
	if err := json.Unmarshal([]byte(response), &rdap); err != nil {
		return model.IPInfo{}, err
	}
	if err := checkCommon(rdap.rdapCommon, model.ObjectClassIPNetwork); err != nil {
		return model.IPInfo{}, err
	}
	start, errStart := netip.ParseAddr(rdap.StartAddress)
	end, errEnd := netip.ParseAddr(rdap.EndAddress)
	if errStart != nil || errEnd != nil {
		return model.IPInfo{}, fmt.Errorf("%w: startAddress %q / endAddress %q", ErrInvalidResponse, rdap.StartAddress, rdap.EndAddress)
	}
	first, last, err := addrRange(query)
	if err != nil {
		return model.IPInfo{}, fmt.Errorf("%w: unparseable query %q: %w", ErrInvalidResponse, query, err)
	}
	start, end = start.Unmap(), end.Unmap()
	// Both endpoints must be in the query's family: netip orders every IPv6
	// address after every IPv4 one, so a mixed range would otherwise pass.
	if start.BitLen() != first.BitLen() || end.BitLen() != first.BitLen() || first.Less(start) || end.Less(last) {
		return model.IPInfo{}, fmt.Errorf("%w: network %s - %s does not cover %s", ErrInvalidResponse, start, end, query)
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
		var prefix string
		if cidr.V4Prefix != "" {
			prefix = fmt.Sprintf("%s/%d", cidr.V4Prefix, int(cidr.Length))
		} else if cidr.V6Prefix != "" {
			prefix = fmt.Sprintf("%s/%d", cidr.V6Prefix, int(cidr.Length))
		} else {
			continue
		}
		info.CIDRs = append(info.CIDRs, prefix)
	}
	if len(info.CIDRs) > 0 {
		// Matches the pre-CIDRs behavior exactly (the loop above used to
		// overwrite a single CIDR field on every iteration, so it held the
		// last entry): existing clients that only read this field must see
		// the same value as before, not a different prefix.
		info.CIDR = info.CIDRs[len(info.CIDRs)-1]
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

// ParseRDAPResponseforASN parses the RDAP response for asn. When the
// response gives its range (startAutnum/endAutnum) the ASN must fall in it.
// Without a range, the handle is all that identifies the object, so it must
// read "AS<number>" for this very ASN; anything else is rejected.
func ParseRDAPResponseforASN(response string, asn uint32) (model.ASNInfo, error) {
	var rdap rdapASNResponse
	if err := json.Unmarshal([]byte(response), &rdap); err != nil {
		return model.ASNInfo{}, err
	}
	if err := checkCommon(rdap.rdapCommon, model.ObjectClassAutnum); err != nil {
		return model.ASNInfo{}, err
	}
	if rdap.StartAutnum != nil && rdap.EndAutnum != nil {
		if asn < *rdap.StartAutnum || asn > *rdap.EndAutnum {
			return model.ASNInfo{}, fmt.Errorf("%w: range AS%d-AS%d does not cover AS%d", ErrInvalidResponse, *rdap.StartAutnum, *rdap.EndAutnum, asn)
		}
	} else if n, ok := handleASN(rdap.Handle); !ok || n != asn {
		return model.ASNInfo{}, fmt.Errorf("%w: no autnum range, and handle %q does not name AS%d", ErrInvalidResponse, rdap.Handle, asn)
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
