package whois

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/KincaidYang/whois/internal/metrics"
	"github.com/KincaidYang/whois/internal/serverlist"
)

const (
	whoisDefaultPort = "43"
	whoisTimeout     = 10 * time.Second
	// maxResponseSize caps how much we read from a WHOIS server to guard
	// against a misbehaving or malicious server exhausting memory.
	maxResponseSize = 2 << 20 // 2 MiB
)

// Whois function is used to query the WHOIS information for a given domain.
func Whois(ctx context.Context, domain, tld string) (result string, err error) {
	start := time.Now()
	defer func() {
		metrics.UpstreamDuration.WithLabelValues("whois", tld).Observe(time.Since(start).Seconds())
	}()
	whoisServer, ok := serverlist.TLDToWhoisServer[tld]
	if !ok {
		return "", fmt.Errorf("no Whois server known for TLD: %s", tld)
	}

	slog.DebugContext(ctx, "querying WHOIS", "domain", domain, "tld", tld, "server", whoisServer)

	// Check if the server address already includes a port
	if _, _, err := net.SplitHostPort(whoisServer); err != nil {
		whoisServer = net.JoinHostPort(whoisServer, whoisDefaultPort)
	}

	d := net.Dialer{Timeout: whoisTimeout}
	conn, err := d.DialContext(ctx, "tcp", whoisServer)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	// Set read/write deadline
	if err := conn.SetDeadline(time.Now().Add(whoisTimeout)); err != nil {
		return "", err
	}

	if _, err := conn.Write([]byte(domain + "\r\n")); err != nil {
		return "", err
	}

	// Read one byte past the limit so an oversized response is detected and
	// rejected rather than silently truncated and cached as if complete.
	body, err := io.ReadAll(io.LimitReader(conn, maxResponseSize+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxResponseSize {
		return "", fmt.Errorf("WHOIS response from %s exceeds %d bytes", whoisServer, maxResponseSize)
	}

	return string(body), nil
}
