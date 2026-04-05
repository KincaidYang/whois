package whois_tools

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/KincaidYang/whois/metrics"
	"github.com/KincaidYang/whois/server_lists"
)

const (
	whoisDefaultPort = "43"
	whoisTimeout     = 10 * time.Second
)

// Whois function is used to query the WHOIS information for a given domain.
func Whois(ctx context.Context, domain, tld string) (result string, err error) {
	start := time.Now()
	defer func() {
		metrics.UpstreamDuration.WithLabelValues("whois").Observe(time.Since(start).Seconds())
	}()
	whoisServer, ok := server_lists.TLDToWhoisServer[tld]
	if !ok {
		return "", fmt.Errorf("no Whois server known for TLD: %s", tld)
	}

	slog.Debug("querying WHOIS", "domain", domain, "tld", tld, "server", whoisServer)

	// Check if the server address already includes a port
	if _, _, err := net.SplitHostPort(whoisServer); err != nil {
		whoisServer = net.JoinHostPort(whoisServer, whoisDefaultPort)
	}

	d := net.Dialer{Timeout: whoisTimeout}
	conn, err := d.DialContext(ctx, "tcp", whoisServer)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Set read/write deadline
	conn.SetDeadline(time.Now().Add(whoisTimeout))

	if _, err := conn.Write([]byte(domain + "\r\n")); err != nil {
		return "", err
	}

	body, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
