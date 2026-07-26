package utils

import "testing"

func TestIsASN(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"AS12345", true},
		{"as12345", true},
		{"asn67890", true},
		{"ASN67890", true},
		{"12345", true},
		{"ASD12345", false},
		{"asn", false},
		{"", false},
	}

	for _, test := range tests {
		result := IsASN(test.input)
		if result != test.expected {
			t.Errorf("IsASN(%q) = %v; want %v", test.input, result, test.expected)
		}
	}
}

func TestClassifyResource(t *testing.T) {
	tests := []struct {
		input     string
		kind      string
		canonical string
	}{
		{"192.0.2.1", KindIP, "192.0.2.1"},
		{"2001:db8::", KindIP, "2001:db8::"},
		// Equivalent spellings of one address must collapse to one canonical
		// form, so they share a cache entry instead of one entry per spelling.
		{"2001:0db8:0:0:0:0:0:1", KindIP, "2001:db8::1"},
		{"2001:db8:0000::0001", KindIP, "2001:db8::1"},
		{"::ffff:192.0.2.1", KindIP, "192.0.2.1"},
		{"192.0.2.0/24", KindIP, "192.0.2.0/24"},
		// A prefix with host bits set names the same network (RFC 9082 defines
		// the ip query as the network), so the bits are masked off.
		{"192.0.2.5/24", KindIP, "192.0.2.0/24"},
		{"2001:db8::1/32", KindIP, "2001:db8::/32"},
		{"192.0.2.0/33", KindUnknown, "192.0.2.0/33"}, // mask too long for IPv4
		{"192.0.2.0/", KindUnknown, "192.0.2.0/"},
		{"as12345", KindASN, "as12345"},
		{"12345", KindASN, "12345"},
		{"example.com", KindDomain, "example.com"},
		{"例子.中国", KindDomain, "例子.中国"}, // normalization is HandleDomain's job
		{"example.com/24", KindUnknown, "example.com/24"},
		{"!!not-valid!!", KindUnknown, "!!not-valid!!"},
		{"", KindUnknown, ""},
	}

	for _, test := range tests {
		kind, canonical := ClassifyResource(test.input)
		if kind != test.kind || canonical != test.canonical {
			t.Errorf("ClassifyResource(%q) = (%q, %q); want (%q, %q)",
				test.input, kind, canonical, test.kind, test.canonical)
		}
	}
}

func TestIsDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"sub.sub.example.com", true},
		{"-example.com", false},
		{"example-.com", false},
		{"example..com", false},
		{"example", false},
		{"123.com", true},
		{"example.c", false},             // TLD too short
		{"exa_mple.com", false},          // Invalid character
		{"müller.de", true},              // IDN (Latin with diacritics)
		{"例子.cn", true},                  // IDN (Chinese label, ASCII TLD)
		{"例子.中国", true},                  // IDN with internationalized (punycode) TLD
		{"xn--fsqu00a.xn--fiqs8s", true}, // already-punycode IDN + punycode TLD
	}

	for _, test := range tests {
		result := IsDomain(test.input)
		if result != test.expected {
			t.Errorf("IsDomain(%q) = %v; want %v", test.input, result, test.expected)
		}
	}
}
