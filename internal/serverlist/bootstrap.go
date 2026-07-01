package serverlist

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/KincaidYang/whois/internal/metrics"
)

// bootstrapResponse is the common structure for IANA RDAP bootstrap JSON files.
// See RFC 9224.
type bootstrapResponse struct {
	Services [][]json.RawMessage `json:"services"`
}

// maxBootstrapResponseSize caps how much we read from an IANA bootstrap file,
// matching the limit on WHOIS/RDAP upstream reads (the dns.json file, the
// largest of the four, is around 200 KB).
const maxBootstrapResponseSize = 2 << 20 // 2 MiB

var ianaBootstrapURLs = map[string]string{
	"dns":  "https://data.iana.org/rdap/dns.json",
	"ipv4": "https://data.iana.org/rdap/ipv4.json",
	"ipv6": "https://data.iana.org/rdap/ipv6.json",
	"asn":  "https://data.iana.org/rdap/asn.json",
}

// fetchBootstrap fetches and parses one IANA bootstrap JSON file.
// Returns a map of identifier → first RDAP server URL.
func fetchBootstrap(ctx context.Context, client *http.Client, url string) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	// Read one byte past the limit so an oversized response is detected and
	// rejected rather than silently truncated.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBootstrapResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBootstrapResponseSize {
		return nil, fmt.Errorf("bootstrap response from %s exceeds %d bytes", url, maxBootstrapResponseSize)
	}

	var bootstrap bootstrapResponse
	if err := json.Unmarshal(body, &bootstrap); err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for _, service := range bootstrap.Services {
		if len(service) < 2 {
			continue
		}

		var identifiers []string
		if err := json.Unmarshal(service[0], &identifiers); err != nil {
			continue
		}

		var urls []string
		if err := json.Unmarshal(service[1], &urls); err != nil || len(urls) == 0 {
			continue
		}

		// Prefer HTTPS; fall back to first URL.
		serverURL := urls[0]
		for _, u := range urls {
			if strings.HasPrefix(u, "https") {
				serverURL = u
				break
			}
		}

		for _, id := range identifiers {
			result[id] = serverURL
		}
	}

	return result, nil
}

// FetchIANA fetches all four IANA bootstrap files and merges them into one map.
// Categories that fail to fetch are omitted from the result (caller uses compiled
// fallback) and their names are returned so the caller can report a partial update
// rather than a clean success.
func FetchIANA(ctx context.Context, client *http.Client) (merged map[string]string, failed []string) {
	merged = make(map[string]string)
	for category, url := range ianaBootstrapURLs {
		data, err := fetchBootstrap(ctx, client, url)
		if err != nil {
			slog.Warn("RDAP bootstrap fetch failed", "category", category, "err", err)
			failed = append(failed, category)
			continue
		}
		for k, v := range data {
			merged[k] = v
		}
		slog.Debug("RDAP bootstrap fetched", "category", category, "entries", len(data))
	}
	return merged, failed
}

// StartBootstrapRefresh fetches IANA data immediately on startup, then
// refreshes on the given interval. Stops when ctx is cancelled.
// interval must be positive; callers should guard with interval > 0.
func StartBootstrapRefresh(ctx context.Context, client *http.Client, interval time.Duration) {
	if interval <= 0 {
		return
	}
	refresh := func() {
		fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		data, failed := FetchIANA(fetchCtx, client)
		if len(data) == 0 {
			slog.Warn("RDAP bootstrap: no data fetched, retaining current index")
			metrics.BootstrapRefreshTotal.WithLabelValues("failure").Inc()
			return
		}
		UpdateFromIANA(data)
		metrics.BootstrapLastFetchTimestamp.Set(float64(time.Now().Unix()))
		if len(failed) > 0 {
			// The failed categories were not in `data`, so UpdateFromIANA just
			// reverted them to the compiled baseline. Surface that instead of
			// reporting a clean success.
			slog.Warn("RDAP bootstrap partially updated; failed categories reverted to compiled baseline",
				"failed", failed, "entries", len(data))
			metrics.BootstrapRefreshTotal.WithLabelValues("partial").Inc()
			return
		}
		metrics.BootstrapRefreshTotal.WithLabelValues("success").Inc()
		slog.Info("RDAP bootstrap index updated", "entries", len(data))
	}

	// Initial fetch at startup (non-blocking).
	go func() {
		refresh()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				refresh()
			case <-ctx.Done():
				return
			}
		}
	}()
}
