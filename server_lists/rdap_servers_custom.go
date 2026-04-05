package server_lists

// customRdapServers contains supplemental or corrective RDAP server entries
// that are not present in (or differ from) the IANA bootstrap data.
// These entries always take precedence over both the compiled-in baseline
// and any live IANA-fetched data.
//
// TLDs listed here support RDAP but are not included in
// https://data.iana.org/rdap/dns.json.
var customRdapServers = map[string]string{
	"us": "https://rdap.nic.us/",
	"me": "https://rdap.identitydigital.services/rdap/",
	"co": "https://rdap.registry.co/co/",
	"de": "https://rdap.denic.de/",
	"io": "https://rdap.donuts.co/rdap/",
	"my": "https://rdap.mynic.my/rdap/",
}
