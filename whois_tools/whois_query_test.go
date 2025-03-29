package whois_tools

import (
	"net"
	"testing"

	"github.com/KincaidYang/whois/server_lists"
)

// Mock server for testing
func startMockWhoisServer(response string) (string, func()) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte(response))
	}()

	return listener.Addr().String(), func() { listener.Close() }
}

func TestWhois(t *testing.T) {
	// Mock WHOIS server response
	mockResponse := "Mock WHOIS response for example.com"
	mockServerAddr, cleanup := startMockWhoisServer(mockResponse)
	defer cleanup()

	// Mock TLDToWhoisServer map
	server_lists.TLDToWhoisServer = map[string]string{
		"com": mockServerAddr,
	}

	// Test case
	domain := "example.com"
	tld := "com"

	result, err := Whois(domain, tld)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result != mockResponse {
		t.Errorf("Expected response %q, got %q", mockResponse, result)
	}
}

func TestWhoisUnknownTLD(t *testing.T) {
	// Mock TLDToWhoisServer map
	server_lists.TLDToWhoisServer = map[string]string{}

	// Test case
	domain := "example.xyz"
	tld := "xyz"

	_, err := Whois(domain, tld)
	if err == nil {
		t.Fatalf("Expected an error for unknown TLD, got none")
	}

	expectedError := "no Whois server known for TLD: xyz"
	if err.Error() != expectedError {
		t.Errorf("Expected error %q, got %q", expectedError, err.Error())
	}
}
