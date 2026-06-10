package mcp

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/handlers"
	"github.com/KincaidYang/whois/internal/utils"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// responseCapture is a minimal http.ResponseWriter that captures the response body and status code.
type responseCapture struct {
	header     http.Header
	statusCode int
	body       bytes.Buffer
}

func newResponseCapture() *responseCapture {
	return &responseCapture{header: make(http.Header)}
}

func (rc *responseCapture) Header() http.Header         { return rc.header }
func (rc *responseCapture) Write(b []byte) (int, error) { return rc.body.Write(b) }
func (rc *responseCapture) WriteHeader(code int)        { rc.statusCode = code }

// WhoisInput defines the input schema for the whois_lookup tool.
type WhoisInput struct {
	Query string `json:"query" jsonschema:"Domain name, IP address (v4/v6), or ASN (e.g. AS12345) to look up"`
}

// errorResult builds a tool result carrying an error message.
func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{
			&mcp.TextContent{Text: msg},
		},
	}
}

func whoisLookup(ctx context.Context, _ *mcp.CallToolRequest, input *WhoisInput) (*mcp.CallToolResult, any, error) {
	// MCP requests consume the same upstream resources as plain HTTP queries,
	// so they share the concurrency limiter, the per-request timeout, and the
	// graceful-shutdown wait group used by the main handler.
	config.Wg.Add(1)
	select {
	case config.ConcurrencyLimiter <- struct{}{}:
	default:
		config.Wg.Done()
		slog.WarnContext(ctx, "rate limit reached", "path", "/mcp")
		return errorResult("too many concurrent requests"), nil, nil
	}
	defer func() {
		config.Wg.Done()
		<-config.ConcurrencyLimiter
	}()

	ctx, cancel := context.WithTimeout(ctx, config.RequestTimeout)
	defer cancel()

	query := strings.TrimSpace(strings.ToLower(input.Query))

	rc := newResponseCapture()
	const cacheKeyPrefix = handlers.CacheKeyPrefix

	if net.ParseIP(query) != nil {
		handlers.HandleIP(ctx, rc, query, cacheKeyPrefix)
	} else if utils.IsASN(query) {
		handlers.HandleASN(ctx, rc, query, cacheKeyPrefix)
	} else if utils.IsDomain(query) {
		handlers.HandleDomain(ctx, rc, query, cacheKeyPrefix, false)
	} else {
		return errorResult("Invalid input: please provide a valid domain, IP address, or ASN"), nil, nil
	}

	statusCode := rc.statusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}

	return &mcp.CallToolResult{
		IsError: statusCode >= 400,
		Content: []mcp.Content{
			&mcp.TextContent{Text: rc.body.String()},
		},
	}, nil, nil
}

// NewHandler returns an http.Handler serving the MCP Streamable HTTP endpoint.
func NewHandler(version string) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "whois",
		Version: version,
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "whois_lookup",
		Description: "Query WHOIS/RDAP information for a domain name, IP address (v4 or v6), or ASN",
	}, whoisLookup)

	return mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return server
	}, &mcp.StreamableHTTPOptions{
		// DNS-rebinding protection rejects requests whose Host header is not
		// localhost. Behind a reverse proxy the Host header is the public
		// domain, so protection is off unless mcp.localhostprotection is set.
		DisableLocalhostProtection: !config.MCPLocalhostProtection,
	})
}
