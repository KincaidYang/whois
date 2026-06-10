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
