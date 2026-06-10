package model

// ASNInfo is the API representation of an autonomous system number. Field
// names follow the RDAP autnum object (RFC 9083 section 5.5).
type ASNInfo struct {
	ObjectClassName  string   `json:"objectClassName"` // always ObjectClassAutnum
	Handle           string   `json:"handle"`
	Name             string   `json:"name,omitempty"`
	Status           []string `json:"status"`
	RegistrationDate string   `json:"registrationDate,omitempty"`
	LastChangedDate  string   `json:"lastChangedDate,omitempty"`
	Remarks          []Remark `json:"remarks,omitempty"`
}
