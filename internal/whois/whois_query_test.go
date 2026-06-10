package whois

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/KincaidYang/whois/internal/serverlist"
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

		// Read data from the client to ensure the connection is properly handled
		buf := make([]byte, 1024)
		_, err = conn.Read(buf)
		if err != nil {
			return
		}

		// Write the mock response
		conn.Write([]byte(response))
	}()

	// Ensure the address is in the correct format
	addr := listener.Addr().String()
	return addr, func() { listener.Close() }
}

func TestWhois(t *testing.T) {
	// Mock WHOIS server response
	mockResponse := "Mock WHOIS response for example.com"
	mockServerAddr, cleanup := startMockWhoisServer(mockResponse)
	defer cleanup()

	// Mock TLDToWhoisServer map
	serverlist.TLDToWhoisServer = map[string]string{
		"com": mockServerAddr,
	}

	// Test case
	domain := "example.com"
	tld := "com"

	result, err := Whois(context.Background(), domain, tld)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result != mockResponse {
		t.Errorf("Expected response %q, got %q", mockResponse, result)
	}
}

func TestWhoisOversizeResponse(t *testing.T) {
	// A response just over the cap must be rejected, not truncated and returned.
	oversized := strings.Repeat("a", maxResponseSize+10)
	mockServerAddr, cleanup := startMockWhoisServer(oversized)
	defer cleanup()

	serverlist.TLDToWhoisServer = map[string]string{"com": mockServerAddr}

	_, err := Whois(context.Background(), "example.com", "com")
	if err == nil {
		t.Fatal("expected an error for oversized WHOIS response, got none")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected size-limit error, got %q", err.Error())
	}
}

func TestWhoisUnknownTLD(t *testing.T) {
	// Mock TLDToWhoisServer map
	serverlist.TLDToWhoisServer = map[string]string{}

	// Test case
	domain := "example.xyz"
	tld := "xyz"

	_, err := Whois(context.Background(), domain, tld)
	if err == nil {
		t.Fatalf("Expected an error for unknown TLD, got none")
	}

	expectedError := "no Whois server known for TLD: xyz"
	if err.Error() != expectedError {
		t.Errorf("Expected error %q, got %q", expectedError, err.Error())
	}
}
