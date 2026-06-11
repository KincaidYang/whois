package model

import (
	"strings"
	"time"
)

// dateTimeLayouts are registry date layouts that include a time of day.
// Layouts without a zone are interpreted in the location passed to
// NormalizeDate.
var dateTimeLayouts = []string{
	time.RFC3339, // also accepts fractional seconds
	"2006-01-02 15:04:05",
	"2006-01-02 15:04",
	"2006/01/02 15:04:05", // .jp
}

// dateOnlyLayouts are registry date layouts with no time of day. They are
// normalized to RFC 3339 full-date (YYYY-MM-DD) without inventing a time,
// since shifting a bare date into UTC could move it across midnight.
var dateOnlyLayouts = []string{
	"2006-01-02",
	"02-01-2006", // .hk
	"2006/01/02", // .jp
	"02-Jan-2006",
	"2006. 01. 02.", // .kr
}

// NormalizeDate parses a registry-provided date string and returns it as
// RFC 3339 UTC, or as RFC 3339 full-date (YYYY-MM-DD) when the registry
// provides no time of day. loc is the zone assumed for layouts that carry no
// offset (use time.UTC when the registry documents UTC). The empty string is
// returned unchanged; an unrecognized format returns ok=false with the
// original string so callers can decide whether to keep or drop it.
func NormalizeDate(s string, loc *time.Location) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", true
	}
	if loc == nil {
		loc = time.UTC
	}
	for _, layout := range dateTimeLayouts {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t.UTC().Format(time.RFC3339), true
		}
	}
	for _, layout := range dateOnlyLayouts {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t.Format("2006-01-02"), true
		}
	}
	return s, false
}

// CleanStatus normalizes registry status values: some registries append the
// ICANN EPP reference URL after the value ("ok https://icann.org/epp#ok");
// the URL is presentation noise and is stripped. Duplicates are removed,
// order is preserved.
func CleanStatus(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if value, url, found := strings.Cut(s, " "); found &&
			(strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "(http")) {
			s = value
		}
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
