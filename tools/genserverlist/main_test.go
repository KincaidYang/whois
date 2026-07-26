package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestQueryIANA verifies how one IANA record is read: the whois: field is the
// server, and a record whose whois: field is empty means the registry has no
// WHOIS server — an answer, not a failure, so those TLDs are simply left out
// of the table. A response that is not a complete record is an error, because
// reading it as "no server" would delete a live entry.
func TestQueryIANA(t *testing.T) {
	for name, tc := range map[string]struct {
		response string
		want     string
		wantErr  bool
	}{
		"server":            {response: "domain:       CN\nwhois:        whois.cnnic.cn\nsource:       IANA\n", want: "whois.cnnic.cn"},
		"empty whois field": {response: "domain:       SAFETY\nwhois:        \nsource:       IANA\n"},
		"no whois field":    {response: "domain:       AQ\nstatus:       ACTIVE\nsource:       IANA\n"},
		"unknown TLD":       {response: "% This query returned 0 objects.\n"},
		"uppercase server":  {response: "domain:       EXAMPLE\nwhois:        WHOIS.NIC.EXAMPLE\nsource:       IANA\n", want: "whois.nic.example"},
		"empty response":    {response: "", wantErr: true},
		"truncated banner":  {response: "% IANA WHOIS server\n", wantErr: true},
		// The dangerous one: enough of the record arrived to look like an
		// answer, but it ended before the whois: field it would have carried.
		"truncated record": {response: "domain:       CN\norganisation: CNNIC\n", wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			addr, gotQuery := fakeWhoisServer(t, tc.response)

			got, err := queryIANA(context.Background(), addr, "example")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got server %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("queryIANA: %v", err)
			}
			if got != tc.want {
				t.Errorf("server = %q, want %q", got, tc.want)
			}
			if q := strings.TrimSpace(<-gotQuery); q != "example" {
				t.Errorf("query sent = %q, want %q", q, "example")
			}
		})
	}
}

// TestLookupWhoisServerRetries verifies a lookup that fails once is retried
// rather than reported as "no server": a dropped connection must never delete
// a live entry from the table.
func TestLookupWhoisServerRetries(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for attempt := 0; ; attempt++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if attempt == 0 {
				// First attempt: hang up without answering.
				_ = conn.Close()
				continue
			}
			buf := make([]byte, 256)
			_, _ = conn.Read(buf) // drain the query so the close is graceful
			_, _ = conn.Write([]byte("domain:       EXAMPLE\nwhois:        whois.nic.example\nsource:       IANA\n"))
			_ = conn.Close()
		}
	}()

	got, err := lookupWhoisServer(context.Background(), listener.Addr().String(), "example")
	if err != nil {
		t.Fatalf("lookupWhoisServer: %v", err)
	}
	if got != "whois.nic.example" {
		t.Errorf("server = %q, want the answer from the retry", got)
	}
}

// TestSortByURLThenKey verifies the ordering convention of the generated RDAP
// file: entries are grouped by server URL, so a registry migration is one
// contiguous block in the diff instead of scattered lines.
func TestSortByURLThenKey(t *testing.T) {
	got := sortByURLThenKey(map[string]string{
		"133.0.0.0/8": "https://rdap.apnic.net/",
		"14.0.0.0/8":  "https://rdap.apnic.net/",
		"1.0.0.0/8":   "https://rdap.apnic.net/",
		"41.0.0.0/8":  "https://rdap.afrinic.net/rdap/",
	})
	want := []string{"41.0.0.0/8", "1.0.0.0/8", "133.0.0.0/8", "14.0.0.0/8"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}

// TestParseStringMap verifies the map of an existing generated file is read
// back for the diff summary, and that a file that does not exist yet counts as
// an empty map rather than an error.
func TestParseStringMap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.go")
	src := `package serverlist

var other = map[string]string{"ignored": "me"}

var servers = map[string]string{
	"cn": "whois.cnnic.cn",
	"xn--fiqs8s": "whois.cnnic.cn",
}
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := parseStringMap(path, "servers")
	if err != nil {
		t.Fatalf("parseStringMap: %v", err)
	}
	want := map[string]string{"cn": "whois.cnnic.cn", "xn--fiqs8s": "whois.cnnic.cn"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("entries = %v, want %v", got, want)
	}

	missing, err := parseStringMap(filepath.Join(dir, "absent.go"), "servers")
	if err != nil {
		t.Fatalf("missing file: %v", err)
	}
	if len(missing) != 0 {
		t.Errorf("missing file returned %v, want an empty map", missing)
	}

	if _, err := parseStringMap(path, "nosuchvar"); err == nil {
		t.Error("expected an error for a variable that is not in the file")
	}
}

// TestWriteCollisions verifies a custom RDAP entry that IANA now publishes
// itself is reported — custom entries override live IANA data, so a stale one
// keeps masking the registry's own answer.
func TestWriteCollisions(t *testing.T) {
	var summary strings.Builder
	custom := map[string]string{
		"de": "https://rdap.denic.de/",
		"io": "https://rdap.donuts.co/rdap/",
		"my": "https://rdap.mynic.my/rdap/",
	}
	fresh := map[string]string{
		"de": "https://rdap.denic.de/",           // redundant: same server
		"io": "https://rdap.identitydigital.se/", // conflicting: different server
	}

	if !writeCollisions(&summary, custom, fresh) {
		t.Fatal("collisions not reported")
	}
	out := summary.String()
	if !strings.Contains(out, "`de`") || !strings.Contains(out, "Now redundant") {
		t.Errorf("redundant entry not reported: %s", out)
	}
	if !strings.Contains(out, "`io`") || !strings.Contains(out, "overrides IANA") {
		t.Errorf("conflicting entry not reported: %s", out)
	}
	if strings.Contains(out, "`my`") {
		t.Errorf("entry IANA still does not publish was reported: %s", out)
	}

	var quiet strings.Builder
	if writeCollisions(&quiet, map[string]string{"my": "https://rdap.mynic.my/rdap/"}, fresh) {
		t.Error("reported a collision for an entry IANA does not publish")
	}
	if quiet.Len() != 0 {
		t.Errorf("wrote %q with nothing to report", quiet.String())
	}
}

// TestWriteDiff verifies the summary names what changed, so the monthly pull
// request can be reviewed without diffing thousands of lines by hand.
func TestWriteDiff(t *testing.T) {
	var summary strings.Builder
	writeDiff(&summary,
		"whois_servers.go",
		map[string]string{"gone": "whois.nic.gone", "moved": "whois.old.example", "same": "whois.same.example"},
		map[string]string{"new": "whois.nic.new", "moved": "whois.new.example", "same": "whois.same.example"},
	)
	out := summary.String()
	for _, want := range []string{
		"3 entries (was 3): 1 added, 1 removed, 1 changed",
		"`new` → whois.nic.new",
		"`gone` (was whois.nic.gone)",
		"`moved`: whois.old.example → whois.new.example",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "`same`") {
		t.Errorf("unchanged entry listed:\n%s", out)
	}

	var unchanged strings.Builder
	writeDiff(&unchanged, "rdap_servers.go", map[string]string{"cn": "x"}, map[string]string{"cn": "x"})
	if !strings.Contains(unchanged.String(), "Unchanged: 1 entries") {
		t.Errorf("unchanged summary = %q", unchanged.String())
	}
}

// fakeWhoisServer answers one connection with response and reports the query
// it received.
func fakeWhoisServer(t *testing.T, response string) (addr string, query <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	received := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		received <- string(buf[:n])
		_, _ = conn.Write([]byte(response))
	}()
	return listener.Addr().String(), received
}
