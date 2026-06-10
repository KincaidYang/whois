package model

import (
	"reflect"
	"testing"
	"time"
)

func TestNormalizeDate(t *testing.T) {
	cst := time.FixedZone("CST", 8*3600)
	tests := []struct {
		in   string
		loc  *time.Location
		want string
		ok   bool
	}{
		{"", nil, "", true},
		{"2026-03-01T12:00:00Z", time.UTC, "2026-03-01T12:00:00Z", true},
		{"2026-03-01T12:00:00.0Z", time.UTC, "2026-03-01T12:00:00Z", true},                   // fractional dropped
		{"2026-03-01T12:00:00+08:00", time.UTC, "2026-03-01T04:00:00Z", true},                // offset honored
		{"2026-03-01 12:00:00", cst, "2026-03-01T04:00:00Z", true},                           // zone-less in CST
		{"2026-03-01", nil, "2026-03-01", true},                                              // date-only stays date-only
		{"01-03-2026", nil, "2026-03-01", true},                                              // .hk DD-MM-YYYY
		{"2026/03/01", nil, "2026-03-01", true},                                              // .jp
		{"2026/03/01 09:00:00", time.FixedZone("JST", 9*3600), "2026-03-01T00:00:00Z", true}, // .jp datetime
		{"not a date", nil, "not a date", false},                                             // passthrough
	}
	for _, tt := range tests {
		got, ok := NormalizeDate(tt.in, tt.loc)
		if got != tt.want || ok != tt.ok {
			t.Errorf("NormalizeDate(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestCleanStatus(t *testing.T) {
	in := []string{
		"clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
		"ok (https://www.icann.org/epp#ok)",
		"active",
		"active", // duplicate
		"  spaced  ",
	}
	want := []string{"clientTransferProhibited", "ok", "active", "spaced"}
	if got := CleanStatus(in); !reflect.DeepEqual(got, want) {
		t.Errorf("CleanStatus = %v, want %v", got, want)
	}
	if got := CleanStatus(nil); got == nil || len(got) != 0 {
		t.Errorf("CleanStatus(nil) = %v, want empty non-nil slice", got)
	}
}
