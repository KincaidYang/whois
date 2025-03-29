package main

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
		result := isASN(test.input)
		if result != test.expected {
			t.Errorf("isASN(%q) = %v; want %v", test.input, result, test.expected)
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
		{"example.c", false},    // TLD too short
		{"exa_mple.com", false}, // Invalid character
	}

	for _, test := range tests {
		result := isDomain(test.input)
		if result != test.expected {
			t.Errorf("isDomain(%q) = %v; want %v", test.input, result, test.expected)
		}
	}
}
