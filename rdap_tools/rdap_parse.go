package rdap_tools

import (
	"encoding/json"
	"fmt"

	"github.com/KincaidYang/whois/rdap_tools/structs"
)

// ParseRDAPResponseforDomain parses the RDAP response for a domain and returns a DomainInfo structure.
func ParseRDAPResponseforDomain(response string) (structs.DomainInfo, error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(response), &result)
	if err != nil {
		return structs.DomainInfo{}, err
	}

	domainInfo := structs.DomainInfo{}

	if ldhName, ok := result["ldhName"]; ok {
		domainInfo.DomainName = ldhName.(string)
	}

	if status, ok := result["status"]; ok {
		domainInfo.DomainStatus = make([]string, len(status.([]interface{})))
		for i, s := range status.([]interface{}) {
			domainInfo.DomainStatus[i] = s.(string)
		}
	}

	if entities, ok := result["entities"]; ok {
		for _, entity := range entities.([]interface{}) {
			if roles, ok := entity.(map[string]interface{})["roles"]; ok {
				for _, role := range roles.([]interface{}) {
					if role.(string) == "registrar" {
						registrarEntity := entity.(map[string]interface{})
						if vcardArray, ok := registrarEntity["vcardArray"]; ok {
							vcardArraySlice, ok := vcardArray.([]interface{})
							if ok && len(vcardArraySlice) > 1 {
								innerSlice, ok := vcardArraySlice[1].([]interface{})
								if ok {
									for _, item := range innerSlice {
										itemSlice, ok := item.([]interface{})
										if ok && len(itemSlice) > 0 {
											if itemSlice[0] == "fn" && len(itemSlice) > 3 {
												domainInfo.Registrar = itemSlice[3].(string)
												break
											}
										}
									}
								}
							}
						}
						if publicIds, ok := registrarEntity["publicIds"]; ok {
							domainInfo.RegistrarIANAID = publicIds.([]interface{})[0].(map[string]interface{})["identifier"].(string)
						}
						break
					}
				}
			}
		}
	}

	if events, ok := result["events"]; ok {
		for _, event := range events.([]interface{}) {
			eventInfo := event.(map[string]interface{})
			switch eventInfo["eventAction"].(string) {
			case "registration":
				domainInfo.CreationDate = eventInfo["eventDate"].(string)
			case "expiration":
				domainInfo.RegistryExpiryDate = eventInfo["eventDate"].(string)
			case "last changed":
				domainInfo.UpdatedDate = eventInfo["eventDate"].(string)
			case "last update of RDAP database":
				domainInfo.LastUpdateOfRDAPDB = eventInfo["eventDate"].(string)
			}
		}
	}

	if nameservers, ok := result["nameservers"]; ok {
		domainInfo.NameServer = make([]string, len(nameservers.([]interface{})))
		for i, ns := range nameservers.([]interface{}) {
			domainInfo.NameServer[i] = ns.(map[string]interface{})["ldhName"].(string)
		}
	}

	domainInfo.DNSSec = "unsigned"
	if secureDNS, ok := result["secureDNS"]; ok {
		if delegationSigned, ok := secureDNS.(map[string]interface{})["delegationSigned"].(bool); ok && delegationSigned {
			domainInfo.DNSSec = "signedDelegation"
			if dsData, ok := secureDNS.(map[string]interface{})["dsData"].([]interface{}); ok && len(dsData) > 0 {
				for _, ds := range dsData {
					dsRecord := ds.(map[string]interface{})
					dsDataStr := fmt.Sprintf("%d %d %d %s",
						int(dsRecord["keyTag"].(float64)),
						int(dsRecord["algorithm"].(float64)),
						int(dsRecord["digestType"].(float64)),
						dsRecord["digest"].(string),
					)
					domainInfo.DNSSecDSData = append(domainInfo.DNSSecDSData, dsDataStr)
				}
			}
		}
	}

	return domainInfo, nil
}

// parseWhoisResponseforIP function is used to parse the WHOIS response for an IP address.
func ParseRDAPResponseforIP(response string) (structs.IPInfo, error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(response), &result)
	if err != nil {
		return structs.IPInfo{}, err
	}

	ipinfo := structs.IPInfo{}

	if handle, ok := result["handle"]; ok {
		ipinfo.IP = handle.(string)
	}

	if startAddress, ok := result["startAddress"]; ok {
		ipinfo.Range = startAddress.(string)
	}

	if endAddress, ok := result["endAddress"]; ok {
		ipinfo.Range += " - " + endAddress.(string)
	}

	if name, ok := result["name"]; ok {
		ipinfo.NetName = name.(string)
	}

	if cidrs, ok := result["cidr0_cidrs"]; ok {
		for _, cidr := range cidrs.([]interface{}) {
			cidrMap := cidr.(map[string]interface{})
			if v4prefix, ok := cidrMap["v4prefix"]; ok {
				length := cidrMap["length"].(float64)
				ipinfo.CIDR = fmt.Sprintf("%s/%d", v4prefix.(string), int(length))
			} else if v6prefix, ok := cidrMap["v6prefix"]; ok {
				length := cidrMap["length"].(float64)
				ipinfo.CIDR = fmt.Sprintf("%s/%d", v6prefix.(string), int(length))
			}
		}
	}

	if type_, ok := result["type"]; ok && type_ != nil {
		ipinfo.Networktype = type_.(string)
	} else {
		ipinfo.Networktype = "Unknown"
	}

	if country, ok := result["country"]; ok {
		ipinfo.Country = country.(string)
	}

	if status, ok := result["status"]; ok {
		ipinfo.IPStatus = make([]string, len(status.([]interface{})))
		for i, s := range status.([]interface{}) {
			ipinfo.IPStatus[i] = s.(string)
		}
	}

	if events, ok := result["events"]; ok {
		for _, event := range events.([]interface{}) {
			eventInfo := event.(map[string]interface{})
			switch eventInfo["eventAction"].(string) {
			case "registration":
				ipinfo.CreationDate = eventInfo["eventDate"].(string)
			case "last changed":
				ipinfo.UpdatedDate = eventInfo["eventDate"].(string)
			}
		}
	}
	return ipinfo, nil
}

// parseRDAPResponseforASN function is used to parse the RDAP response for an ASN.
func ParseRDAPResponseforASN(response string) (structs.ASNInfo, error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(response), &result)
	if err != nil {
		return structs.ASNInfo{}, err
	}

	asninfo := structs.ASNInfo{}

	if handle, ok := result["handle"]; ok {
		asninfo.ASN = handle.(string)
	}

	if name, ok := result["name"]; ok {
		asninfo.ASName = name.(string)
	}

	if status, ok := result["status"]; ok {
		asninfo.ASStatus = make([]string, len(status.([]interface{})))
		for i, s := range status.([]interface{}) {
			asninfo.ASStatus[i] = s.(string)
		}
	}

	if events, ok := result["events"]; ok {
		for _, event := range events.([]interface{}) {
			eventInfo := event.(map[string]interface{})
			switch eventInfo["eventAction"].(string) {
			case "registration":
				asninfo.CreationDate = eventInfo["eventDate"].(string)
			case "last changed":
				asninfo.UpdatedDate = eventInfo["eventDate"].(string)
			}
		}
	}
	return asninfo, nil
}
