package structs

// IPInfo represents the information about an IP network.
type IPInfo struct {
	IP           string   `json:"IP Network"`    // IP is the IP network.
	Range        string   `json:"Address Range"` // Range is the address range of the IP network.
	NetName      string   `json:"Network Name"`  // NetName is the name of the network.
	CIDR         string   `json:"CIDR"`          // CIDR is the CIDR of the IP network.
	Networktype  string   `json:"Network Type"`  // Networktype is the type of the network.
	Country      string   `json:"Country"`       // Country is the country of the IP network.
	IPStatus     []string `json:"Status"`        // IPStatus is the status of the IP network.
	CreationDate string   `json:"Creation Date"` // CreationDate is the creation date of the IP network.
	UpdatedDate  string   `json:"Updated Date"`  // UpdatedDate is the updated date of the IP network.
}
