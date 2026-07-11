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

// FetchIANA fetches all four IANA bootstrap files. Results are keyed by
// category so the caller can commit each independently; categories that fail
// to fetch are absent from the map and listed in failed, so the caller can
// report a partial update rather than a clean success.
func FetchIANA(ctx context.Context, client *http.Client) (perCategory map[string]map[string]string, failed []string) {
	perCategory = make(map[string]map[string]string)
	for category, url := range ianaBootstrapURLs {
		data, err := fetchBootstrap(ctx, client, url)
		if err != nil {
			slog.Warn("RDAP bootstrap fetch failed", "category", category, "err", err)
			failed = append(failed, category)
			continue
		}
		perCategory[category] = data
		slog.Debug("RDAP bootstrap fetched", "category", category, "entries", len(data))
	}
	return perCategory, failed
}

// commitBootstrap folds one round of per-category fetch results into
// lastGood and rebuilds the active index from every category's last-known-good
// data, so a category whose refresh failed keeps serving its most recent
// successful fetch instead of reverting to the compiled baseline. With
// consecutive failures that data can be several intervals stale — staleness
// is unbounded, traded for availability; each failed round is visible in the
// logs and the refresh metric. It returns the outcome label for the metric —
// "failure" (nothing fetched, index untouched), "partial" or "success" —
// and the number of entries committed.
func commitBootstrap(lastGood, perCategory map[string]map[string]string, failed []string) (outcome string, entries int) {
	if len(perCategory) == 0 {
		return "failure", 0
	}
	for category, data := range perCategory {
		lastGood[category] = data
	}
	merged := make(map[string]string)
	for _, data := range lastGood {
		for k, v := range data {
			merged[k] = v
		}
	}
	UpdateFromIANA(merged)
	if len(failed) > 0 {
		return "partial", len(merged)
	}
	return "success", len(merged)
}

// StartBootstrapRefresh fetches IANA data immediately on startup, then
// refreshes on the given interval. Stops when ctx is cancelled.
// interval must be positive; callers should guard with interval > 0.
func StartBootstrapRefresh(ctx context.Context, client *http.Client, interval time.Duration) {
	if interval <= 0 {
		return
	}
	// lastGood holds each category's most recent successful fetch. refresh
	// only ever runs on the single goroutine below, so no locking is needed.
	lastGood := make(map[string]map[string]string)
	refresh := func() {
		fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		perCategory, failed := FetchIANA(fetchCtx, client)
		outcome, entries := commitBootstrap(lastGood, perCategory, failed)
		metrics.BootstrapRefreshTotal.WithLabelValues(outcome).Inc()
		switch outcome {
		case "failure":
			slog.Warn("RDAP bootstrap: no data fetched, retaining current index")
		case "partial":
			slog.Warn("RDAP bootstrap partially updated; failed categories retain last-known-good data",
				"failed", failed, "entries", entries)
		default:
			metrics.BootstrapLastFetchTimestamp.Set(float64(time.Now().Unix()))
			slog.Info("RDAP bootstrap index updated", "entries", entries)
		}
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
