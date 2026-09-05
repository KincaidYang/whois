package model

// IPInfo is the API representation of an IP network. Field names follow the
// RDAP ip network object (RFC 9083 section 5.4).
type IPInfo struct {
	ObjectClassName string `json:"objectClassName"` // always ObjectClassIPNetwork
	Handle          string `json:"handle"`
	StartAddress    string `json:"startAddress,omitempty"`
	EndAddress      string `json:"endAddress,omitempty"`
	// CIDR is the first entry of CIDRs, kept for backward compatibility with
	// clients that only read a single prefix.
	CIDR string `json:"cidr,omitempty"`
	// CIDRs holds every prefix the RDAP response listed (cidr0_cidrs); a
	// network can be announced as more than one CIDR block.
	CIDRs            []string `json:"cidrs,omitempty"`
	Name             string   `json:"name,omitempty"`
	Type             string   `json:"type,omitempty"`
	Country          string   `json:"country,omitempty"`
	Status           []string `json:"status"`
	RegistrationDate string   `json:"registrationDate,omitempty"`
	LastChangedDate  string   `json:"lastChangedDate,omitempty"`
	Remarks          []Remark `json:"remarks,omitempty"`
}

// Remark is additional registry-provided information (RFC 9083 section 4.3).
type Remark struct {
	Title       string   `json:"title"`
	Description []string `json:"description"`
}
