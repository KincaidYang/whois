package server_lists

// customRdapServers contains supplemental or corrective RDAP server entries
// that are not present in (or differ from) the IANA bootstrap data.
// These entries always take precedence over both the compiled-in baseline
// and any live IANA-fetched data.
var customRdapServers = map[string]string{}
