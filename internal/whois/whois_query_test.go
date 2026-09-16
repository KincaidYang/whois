package whois

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

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
		defer func() { _ = conn.Close() }()

		// Read data from the client to ensure the connection is properly handled
		buf := make([]byte, 1024)
		_, err = conn.Read(buf)
		if err != nil {
			return
		}

		// Write the mock response
		_, _ = conn.Write([]byte(response))
	}()

	// Ensure the address is in the correct format
	addr := listener.Addr().String()
	return addr, func() { _ = listener.Close() }
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

// TestWhoisRespectsContextDeadlineAfterDial verifies a connection established
// but then never answered is abandoned once ctx's own (shorter) deadline
// passes, rather than always waiting out the full whoisTimeout (10s), which
// only DialContext honors on its own.
func TestWhoisRespectsContextDeadlineAfterDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	connCh := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		connCh <- conn
		// Consume the query but never write a response: the client must be
		// the one to give up, via ctx, not the server closing the connection.
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
	}()

	serverlist.TLDToWhoisServer = map[string]string{"com": listener.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = Whois(ctx, "example.com", "com")
	elapsed := time.Since(start)

	if conn := <-connCh; conn != nil {
		defer func() { _ = conn.Close() }()
	}

	if err == nil {
		t.Fatal("expected a timeout error, got none")
	}
	// Generous upper bound: must return well before the 10s whoisTimeout,
	// not just eventually.
	if elapsed > 2*time.Second {
		t.Errorf("Whois took %v to respect ctx's 200ms deadline (whoisTimeout is 10s)", elapsed)
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
