package server_lists

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// bootstrapResponse is the common structure for IANA RDAP bootstrap JSON files.
// See RFC 9224.
type bootstrapResponse struct {
	Services [][]json.RawMessage `json:"services"`
}

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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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
			if len(u) >= 5 && u[:5] == "https" {
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
// Categories that fail to fetch are omitted from the result (caller uses compiled fallback).
func FetchIANA(ctx context.Context, client *http.Client) map[string]string {
	merged := make(map[string]string)
	for category, url := range ianaBootstrapURLs {
		data, err := fetchBootstrap(ctx, client, url)
		if err != nil {
			slog.Warn("RDAP bootstrap fetch failed", "category", category, "err", err)
			continue
		}
		for k, v := range data {
			merged[k] = v
		}
		slog.Debug("RDAP bootstrap fetched", "category", category, "entries", len(data))
	}
	return merged
}

// StartBootstrapRefresh fetches IANA data immediately on startup, then
// refreshes on the given interval. Stops when ctx is cancelled.
func StartBootstrapRefresh(ctx context.Context, client *http.Client, interval time.Duration) {
	refresh := func() {
		fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		data := FetchIANA(fetchCtx, client)
		if len(data) == 0 {
			slog.Warn("RDAP bootstrap: no data fetched, retaining current index")
			return
		}
		UpdateFromIANA(data)
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
