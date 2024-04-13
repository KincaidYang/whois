package whois_tools

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/KincaidYang/whois/server_lists"
)

// Whois function is used to query the WHOIS information for a given domain.
func Whois(domain, tld string) (string, error) {
	whoisServer, ok := server_lists.TLDToWhoisServer[tld]
	if !ok {
		return "", fmt.Errorf("no Whois server known for TLD: %s", tld)
	}

	// Log the request for the WHOIS query
	log.Printf("Querying WHOIS for domain: %s with TLD: %s on server: %s\n", domain, tld, whoisServer)

	conn, err := net.Dial("tcp", whoisServer+":43")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.Write([]byte(domain + "\r\n"))
	var buf bytes.Buffer
	_, err = io.Copy(&buf, conn)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}
