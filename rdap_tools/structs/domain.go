package structs

// DomainInfo represents the information about a domain.
type DomainInfo struct {
	DomainName         string   `json:"Domain Name"`             // DomainName is the name of the domain.
	Registrar          string   `json:"Registrar"`               // Registrar is the registrar of the domain.
	RegistrarIANAID    string   `json:"Registrar IANA ID"`       // RegistrarIANAID is the IANA ID of the registrar.
	DomainStatus       []string `json:"Domain Status"`           // DomainStatus is the status of the domain.
	CreationDate       string   `json:"Creation Date"`           // CreationDate is the creation date of the domain.
	RegistryExpiryDate string   `json:"Registry Expiry Date"`    // RegistryExpiryDate is the expiry date of the domain.
	UpdatedDate        string   `json:"Updated Date"`            // UpdatedDate is the updated date of the domain.
	NameServer         []string `json:"Name Server"`             // NameServer is the name server of the domain.
	DNSSec             string   `json:"DNSSEC"`                  // DNSSec is the DNSSEC of the domain.
	DNSSecDSData       []string `json:"DNSSEC DS Data"`          // DNSSecDSData is the DNSSEC DS Data of the domain.
	LastUpdateOfRDAPDB string   `json:"Last Update of Database"` // LastUpdateOfRDAPDB is the last update of the database.
}
