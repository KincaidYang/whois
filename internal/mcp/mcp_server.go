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
	"github.com/KincaidYang/whois/internal/metrics"
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

// Tool calls are reported under the same metrics as the HTTP query endpoints,
// as their own resource types. Without this, the MCP endpoint — the one this
// project leads with — is invisible in everything except the per-key client
// counter, which only exists when authentication is enabled.
const (
	toolTypeLookup = "mcp"
	toolTypeBatch  = "mcp_batch"
)

// countTool records a tool call rejected before any lookup happened. Like the
// HTTP handler's own rejections, these get no latency observation: they say
// nothing about how long a query takes.
func countTool(tool string, status int) {
	metrics.HTTPRequestsTotal.WithLabelValues(tool, strconv.Itoa(status)).Inc()
}

// recordTool records a tool call that ran, with the status the query itself
// produced (200, 404, 400 …), so MCP traffic is comparable with the same
// resource's HTTP traffic.
func recordTool(tool string, status int, start time.Time) {
	countTool(tool, status)
	metrics.HTTPRequestDuration.WithLabelValues(tool).Observe(time.Since(start).Seconds())
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
	start := time.Now()

	// MCP requests consume the same upstream resources as plain HTTP queries,
	// so they share the concurrency limiter, the per-request timeout, and the
	// graceful-shutdown wait group used by the main handler.
	config.Wg.Add(1)
	select {
	case config.ConcurrencyLimiter <- struct{}{}:
	default:
		config.Wg.Done()
		slog.WarnContext(ctx, "rate limit reached", "path", "/mcp")
		countTool(toolTypeLookup, http.StatusTooManyRequests)
		return errorResult("too many concurrent requests"), nil, nil
	}
	defer func() {
		config.Wg.Done()
		<-config.ConcurrencyLimiter
	}()

	ctx, cancel := context.WithTimeout(ctx, config.RequestTimeout)
	defer cancel()

	kind, query := utils.ClassifyResource(strings.TrimSpace(strings.ToLower(input.Query)))

	rc := handlers.NewResponseCapture()
	const cacheKeyPrefix = handlers.CacheKeyPrefix

	switch kind {
	case utils.KindIP:
		handlers.HandleIP(ctx, rc, query, cacheKeyPrefix, false)
	case utils.KindASN:
		handlers.HandleASN(ctx, rc, query, cacheKeyPrefix, false)
	case utils.KindDomain:
		handlers.HandleDomain(ctx, rc, query, cacheKeyPrefix, false, false)
	default:
		recordTool(toolTypeLookup, http.StatusBadRequest, start)
		return errorResult("Invalid input: please provide a valid domain, IP address, or ASN"), nil, nil
	}

	recordTool(toolTypeLookup, rc.StatusCode(), start)
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
	start := time.Now()

	if !config.BatchEnabled {
		countTool(toolTypeBatch, http.StatusForbidden)
		return errorResult("Batch queries are disabled on this instance (batch.enabled)"), nil, nil
	}
	if len(input.Queries) == 0 {
		countTool(toolTypeBatch, http.StatusBadRequest)
		return errorResult("The queries list must not be empty"), nil, nil
	}
	if len(input.Queries) > config.BatchMaxItems {
		countTool(toolTypeBatch, http.StatusBadRequest)
		return errorResult("Too many queries in one batch: the limit on this instance is " + strconv.Itoa(config.BatchMaxItems)), nil, nil
	}

	config.Wg.Add(1)
	select {
	case config.ConcurrencyLimiter <- struct{}{}:
	default:
		config.Wg.Done()
		slog.WarnContext(ctx, "rate limit reached", "path", "/mcp")
		countTool(toolTypeBatch, http.StatusTooManyRequests)
		return errorResult("too many concurrent requests"), nil, nil
	}
	defer func() {
		config.Wg.Done()
		<-config.ConcurrencyLimiter
	}()

	if client := config.AuthClientFromContext(ctx); client != nil && client.Limiter != nil && len(input.Queries) > 1 {
		reservation := client.Limiter.ReserveN(time.Now(), len(input.Queries)-1)
		if !reservation.OK() {
			countTool(toolTypeBatch, http.StatusTooManyRequests)
			return errorResult("The batch exceeds the API key's per-minute request budget; reduce the batch size"), nil, nil
		}
		if delay := reservation.Delay(); delay > 0 {
			reservation.Cancel()
			countTool(toolTypeBatch, http.StatusTooManyRequests)
			return errorResult("The API key's request budget is exhausted; retry in " + delay.Round(time.Second).String()), nil, nil
		}
	}

	ctx, cancel := context.WithTimeout(ctx, config.RequestTimeout)
	defer cancel()

	results := handlers.RunBatch(ctx, input.Queries)
	payload, err := json.Marshal(handlers.BatchResponse{Results: results})
	if err != nil {
		recordTool(toolTypeBatch, http.StatusInternalServerError, start)
		return errorResult("failed to encode batch results"), nil, nil
	}

	isError := true
	for _, item := range results {
		if item.Status < 400 {
			isError = false
			break
		}
	}

	// The batch itself succeeded; per-item statuses are in the payload.
	recordTool(toolTypeBatch, http.StatusOK, start)
	return &mcp.CallToolResult{
		IsError: isError,
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(payload)},
		},
	}, nil, nil
}

// discoveryTTL is how long clients may cache the tool list and the discovery
// response. Both are fixed at build time — the tools are registered here and
// never change while the process runs, and whois_batch_lookup stays listed
// even when batch queries are off (it reports that itself when called), so
// nothing an operator can toggle invalidates a cached list. An hour keeps
// long-lived clients from re-listing on every conversation while still
// picking up a new tool within an hour of an upgrade.
const discoveryTTL = time.Hour

// withCacheHints stamps the TTL hint introduced in protocol revision
// 2026-07-28 onto the two results that carry one here. The SDK defaults TTLMs
// to 0, which tells clients the response is immediately stale. The scope stays
// the SDK's "public": the tool list is the same for every caller, including
// when API key authentication is on.
func withCacheHints(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		if err != nil {
			return res, err
		}
		ttl := int(discoveryTTL.Milliseconds())
		switch r := res.(type) {
		case *mcp.ListToolsResult:
			r.TTLMs = ttl
		case *mcp.DiscoverResult:
			r.TTLMs = ttl
		}
		return res, nil
	}
}

// readOnly marks a tool as one that only reads. Every tool here answers a
// lookup and changes nothing, which lets clients skip the confirmation
// prompt they put in front of tools that can act. DestructiveHint is left
// unset because it is meaningful only when ReadOnlyHint is false, and
// OpenWorldHint because these tools do query an open world of registries,
// which is its default.
func readOnly(title string) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{Title: title, ReadOnlyHint: true}
}

// NewHandler returns an http.Handler serving the MCP Streamable HTTP endpoint.
func NewHandler(version string) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "whois",
		Version: version,
	}, nil)
	server.AddReceivingMiddleware(withCacheHints)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "whois_lookup",
		Description: "Query WHOIS/RDAP information for a domain name, IP address or CIDR prefix (v4 or v6), or ASN",
		Annotations: readOnly("WHOIS/RDAP lookup"),
	}, whoisLookup)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "whois_batch_lookup",
		Description: "Query WHOIS/RDAP information for multiple domain names, IP addresses/CIDR prefixes, or ASNs in one call. Results are returned per query with individual statuses. Disabled unless the operator enables batch queries.",
		Annotations: readOnly("Bulk WHOIS/RDAP lookup"),
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
