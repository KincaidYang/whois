package model

// RDAP object class names (RFC 9083 section 4.7) used as the
// objectClassName discriminator on responses.
const (
	ObjectClassDomain    = "domain"
	ObjectClassIPNetwork = "ip network"
	ObjectClassAutnum    = "autnum"
)

// DSData is a DNSSEC delegation signer record (RFC 9083 section 5.3).
type DSData struct {
	KeyTag     int    `json:"keyTag"`
	Algorithm  int    `json:"algorithm"`
	DigestType int    `json:"digestType"`
	Digest     string `json:"digest"`
}

// SecureDNS describes the DNSSEC state of a domain (RFC 9083 section 5.3).
type SecureDNS struct {
	DelegationSigned bool     `json:"delegationSigned"`
	DSData           []DSData `json:"dsData,omitempty"`
}

// DomainInfo is the API representation of a domain. Field names follow the
// RDAP JSON vocabulary (RFC 9083); dates are RFC 3339 UTC (date-only when the
// registry provides no time of day).
type DomainInfo struct {
	ObjectClassName    string     `json:"objectClassName"` // always ObjectClassDomain
	LdhName            string     `json:"ldhName"`
	UnicodeName        string     `json:"unicodeName,omitempty"`
	Registrar          string     `json:"registrar,omitempty"`
	RegistrarIANAID    string     `json:"registrarIanaId,omitempty"`
	Status             []string   `json:"status"`
	RegistrationDate   string     `json:"registrationDate,omitempty"`
	ExpirationDate     string     `json:"expirationDate,omitempty"`
	LastChangedDate    string     `json:"lastChangedDate,omitempty"`
	Nameservers        []string   `json:"nameservers"`
	SecureDNS          *SecureDNS `json:"secureDNS,omitempty"`
	LastUpdateOfRdapDb string     `json:"lastUpdateOfRdapDb,omitempty"`

	// Unparsed and RawText are set when no parser exists for the TLD: the
	// registry's WHOIS text is returned verbatim instead of parsed fields.
	Unparsed bool   `json:"unparsed,omitempty"`
	RawText  string `json:"rawText,omitempty"`
}
