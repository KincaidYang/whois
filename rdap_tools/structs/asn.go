package structs

// ASNInfo represents the information about an Autonomous System Number (ASN).
type ASNInfo struct {
	ASN          string   `json:"AS Number"`     // ASN is the Autonomous System Number.
	ASName       string   `json:"Network Name"`  // ASName is the name of the network.
	ASStatus     []string `json:"Status"`        // ASStatus is the status of the ASN.
	CreationDate string   `json:"Creation Date"` // CreationDate is the creation date of the ASN.
	UpdatedDate  string   `json:"Updated Date"`  // UpdatedDate is the updated date of the ASN.
}
