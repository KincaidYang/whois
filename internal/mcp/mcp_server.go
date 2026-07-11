package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/handlers"
	"github.com/KincaidYang/whois/internal/utils"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// WhoisInput defines the input schema for the whois_lookup tool.
type WhoisInput struct {
	Query string `json:"query" jsonschema:"Domain name, IP address (v4/v6), or ASN (e.g. AS12345) to look up"`
}

// BatchInput defines the input schema for the whois_batch_lookup tool.
type BatchInput struct {
	Queries []string `json:"queries" jsonschema:"Domain names, IP addresses (v4/v6), or ASNs (e.g. AS12345) to look up"`
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

	rc := handlers.NewResponseCapture()
	const cacheKeyPrefix = handlers.CacheKeyPrefix

	if utils.IsIP(query) || utils.IsCIDR(query) {
		handlers.HandleIP(ctx, rc, query, cacheKeyPrefix, false)
	} else if utils.IsASN(query) {
		handlers.HandleASN(ctx, rc, query, cacheKeyPrefix, false)
	} else if utils.IsDomain(query) {
		handlers.HandleDomain(ctx, rc, query, cacheKeyPrefix, false, false)
	} else {
		return errorResult("Invalid input: please provide a valid domain, IP address, or ASN"), nil, nil
	}

	return &mcp.CallToolResult{
		IsError: rc.StatusCode() >= 400,
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(rc.Body())},
		},
	}, nil, nil
}

// whoisBatchLookup answers the whois_batch_lookup tool: the MCP face of the
// /batch endpoint, under the same enablement flag, size cap and rate-limit
// accounting (the HTTP layer charged one token; the rest are charged here).
func whoisBatchLookup(ctx context.Context, _ *mcp.CallToolRequest, input *BatchInput) (*mcp.CallToolResult, any, error) {
	if !config.BatchEnabled {
		return errorResult("Batch queries are disabled on this instance (batch.enabled)"), nil, nil
	}
	if len(input.Queries) == 0 {
		return errorResult("The queries list must not be empty"), nil, nil
	}
	if len(input.Queries) > config.BatchMaxItems {
		return errorResult("Too many queries in one batch: the limit on this instance is " + strconv.Itoa(config.BatchMaxItems)), nil, nil
	}

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

	if client := config.AuthClientFromContext(ctx); client != nil && client.Limiter != nil && len(input.Queries) > 1 {
		reservation := client.Limiter.ReserveN(time.Now(), len(input.Queries)-1)
		if !reservation.OK() {
			return errorResult("The batch exceeds the API key's per-minute request budget; reduce the batch size"), nil, nil
		}
		if delay := reservation.Delay(); delay > 0 {
			reservation.Cancel()
			return errorResult("The API key's request budget is exhausted; retry in " + delay.Round(time.Second).String()), nil, nil
		}
	}

	ctx, cancel := context.WithTimeout(ctx, config.RequestTimeout)
	defer cancel()

	results := handlers.RunBatch(ctx, input.Queries)
	payload, err := json.Marshal(handlers.BatchResponse{Results: results})
	if err != nil {
		return errorResult("failed to encode batch results"), nil, nil
	}

	isError := true
	for _, item := range results {
		if item.Status < 400 {
			isError = false
			break
		}
	}

	return &mcp.CallToolResult{
		IsError: isError,
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(payload)},
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
		Description: "Query WHOIS/RDAP information for a domain name, IP address or CIDR prefix (v4 or v6), or ASN",
	}, whoisLookup)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "whois_batch_lookup",
		Description: "Query WHOIS/RDAP information for multiple domain names, IP addresses/CIDR prefixes, or ASNs in one call. Results are returned per query with individual statuses. Disabled unless the operator enables batch queries.",
	}, whoisBatchLookup)

	return mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return server
	}, &mcp.StreamableHTTPOptions{
		// DNS-rebinding protection rejects requests whose Host header is not
		// localhost. Behind a reverse proxy the Host header is the public
		// domain, so protection is off unless mcp.localhostprotection is set.
		DisableLocalhostProtection: !config.MCPLocalhostProtection,
		// The server only exposes tools — it never sends notifications or
		// server-initiated requests — so sessions carry no state worth keeping.
		// Stateless mode closes the per-request session when the request ends
		// (idle stateful sessions are otherwise never cleaned up, since
		// SessionTimeout's zero value disables cleanup), and JSONResponse
		// answers tool calls with plain application/json instead of an SSE
		// stream, which the server's global WriteTimeout would cut short.
		Stateless:    true,
		JSONResponse: true,
	})
}
