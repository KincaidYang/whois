package serverlist

import "testing"

// TestCommitBootstrapLastKnownGood verifies that a category whose refresh
// fails keeps serving its most recent successful fetch instead of reverting
// to the compiled baseline, and that outcomes are labelled correctly.
func TestCommitBootstrapLastKnownGood(t *testing.T) {
	t.Cleanup(func() { UpdateFromIANA(nil) })

	lastGood := make(map[string]map[string]string)

	// Round 1: both categories fetch successfully. The zzlkg TLD exists only
	// in the fetched data, never in the compiled baseline, so its survival
	// proves last-known-good retention.
	outcome, entries := commitBootstrap(lastGood, map[string]map[string]string{
		"dns":  {"zzlkg": "https://round1.example/rdap/"},
		"ipv4": {"192.0.2.0/24": "https://round1.example/rdap/"},
	}, nil)
	if outcome != "success" || entries != 2 {
		t.Fatalf("round 1: outcome=%q entries=%d, want success/2", outcome, entries)
	}

	// Round 2: dns fails, ipv4 fetches fresh data.
	outcome, entries = commitBootstrap(lastGood, map[string]map[string]string{
		"ipv4": {"192.0.2.0/24": "https://round2.example/rdap/"},
	}, []string{"dns"})
	if outcome != "partial" || entries != 2 {
		t.Fatalf("round 2: outcome=%q entries=%d, want partial/2", outcome, entries)
	}
	if url, ok := LookupRdapServer("zzlkg"); !ok || url != "https://round1.example/rdap/" {
		t.Errorf("failed dns category: zzlkg = %q, %v; want round-1 last-known-good data", url, ok)
	}
	if url, ok := LookupRdapServer("192.0.2.0/24"); !ok || url != "https://round2.example/rdap/" {
		t.Errorf("refreshed ipv4 category: got %q, %v; want round-2 data", url, ok)
	}

	// Round 3: everything fails; the index must be left untouched.
	outcome, entries = commitBootstrap(lastGood, map[string]map[string]string{}, []string{"dns", "ipv4", "ipv6", "asn"})
	if outcome != "failure" || entries != 0 {
		t.Fatalf("round 3: outcome=%q entries=%d, want failure/0", outcome, entries)
	}
	if url, ok := LookupRdapServer("zzlkg"); !ok || url != "https://round1.example/rdap/" {
		t.Errorf("total failure: zzlkg = %q, %v; want index untouched", url, ok)
	}
}
