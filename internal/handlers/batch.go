package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KincaidYang/whois/internal/config"
	"github.com/KincaidYang/whois/internal/utils"
)

// batchConcurrency caps how many of one batch's queries run upstream at the
// same time. The whole batch shares one request timeout, so items beyond the
// first waves of a slow batch may individually time out rather than extend
// the request.
const batchConcurrency = 5

// maxBatchBody bounds the /batch request body; batches are short lists of
// domain names, IPs and ASNs, so anything bigger is a mistake or abuse.
const maxBatchBody = 64 << 10 // 64 KiB

// ResponseCapture is a minimal http.ResponseWriter that buffers the response
// instead of sending it, so an http handler can be reused as an in-process
// query function (the MCP tools and the batch endpoint do this).
type ResponseCapture struct {
	header     http.Header
	statusCode int
	body       bytes.Buffer
}

// NewResponseCapture returns an empty capture ready to be written to.
func NewResponseCapture() *ResponseCapture {
	return &ResponseCapture{header: make(http.Header)}
}

func (rc *ResponseCapture) Header() http.Header         { return rc.header }
func (rc *ResponseCapture) Write(b []byte) (int, error) { return rc.body.Write(b) }
func (rc *ResponseCapture) WriteHeader(code int)        { rc.statusCode = code }

// StatusCode returns the captured status code, defaulting to 200 when the
// handler never called WriteHeader.
func (rc *ResponseCapture) StatusCode() int {
	if rc.statusCode == 0 {
		return http.StatusOK
	}
	return rc.statusCode
}

// Body returns the captured response body.
func (rc *ResponseCapture) Body() []byte { return rc.body.Bytes() }

// BatchRequest is the POST /batch request body.
type BatchRequest struct {
	Queries []string `json:"queries"`
}

// BatchItem is the outcome of one query in a batch: Data carries the regular
// response object on success, Error the RFC 9457 problem object on failure.
type BatchItem struct {
	Query  string          `json:"query"`
	Status int             `json:"status"`
	Data   json.RawMessage `json:"data,omitempty"`
	Error  json.RawMessage `json:"error,omitempty"`
}

// BatchResponse is the POST /batch response body.
type BatchResponse struct {
	Results []BatchItem `json:"results"`
}

// HandleBatch serves POST /batch: a list of mixed domain/IP/ASN queries
// answered item by item. The response is always 200 with per-item statuses;
// request-level failures (disabled, oversized, malformed, over budget) are
// problem responses.
func HandleBatch(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if !config.BatchEnabled {
		utils.WriteBatchDisabled(w)
		return
	}

	var req BatchRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBatchBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		utils.HandleHTTPError(w, utils.ErrorTypeBadRequest, "Invalid request body: expected {\"queries\": [\"example.com\", ...]}.")
		return
	}
	if len(req.Queries) == 0 {
		utils.HandleHTTPError(w, utils.ErrorTypeBadRequest, "The queries list must not be empty.")
		return
	}
	if len(req.Queries) > config.BatchMaxItems {
		utils.HandleHTTPError(w, utils.ErrorTypeBadRequest,
			"Too many queries in one batch: the limit on this instance is "+strconv.Itoa(config.BatchMaxItems)+".")
		return
	}

	// The auth middleware charged one rate-limit token for the request;
	// charge the remaining N-1 so a batch costs as many tokens as the same
	// queries sent one by one, and the per-key limit cannot be bypassed.
	if client := config.AuthClientFromContext(ctx); client != nil && client.Limiter != nil && len(req.Queries) > 1 {
		reservation := client.Limiter.ReserveN(time.Now(), len(req.Queries)-1)
		if !reservation.OK() {
			utils.WriteRateLimitedBatch(w)
			return
		}
		if delay := reservation.Delay(); delay > 0 {
			reservation.Cancel()
			utils.WriteRateLimitedAfter(w, delay)
			return
		}
	}

	results := RunBatch(ctx, req.Queries)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(BatchResponse{Results: results})
}

// RunBatch answers each query with bounded concurrency. Items share the
// caller's context: when the request deadline expires, unfinished items
// report their individual timeout errors. Duplicate in-flight queries are
// collapsed by the singleflight layer the handlers already use. Shared by
// the HTTP /batch endpoint and the MCP whois_batch_lookup tool.
func RunBatch(ctx context.Context, queries []string) []BatchItem {
	results := make([]BatchItem, len(queries))
	sem := make(chan struct{}, batchConcurrency)
	var wg sync.WaitGroup
	for i, query := range queries {
		wg.Add(1)
		go func(i int, query string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = runBatchItem(ctx, query)
		}(i, query)
	}
	wg.Wait()
	return results
}

// runBatchItem answers one batch query by dispatching to the regular
// domain/IP/ASN handlers against a capture writer, exactly like a single
// query (cache, singleflight and negative caching all apply).
func runBatchItem(ctx context.Context, query string) BatchItem {
	item := BatchItem{Query: query}
	normalized := strings.ToLower(strings.TrimSpace(query))

	rc := NewResponseCapture()
	switch {
	case utils.IsIP(normalized) || utils.IsCIDR(normalized):
		HandleIP(ctx, rc, normalized, CacheKeyPrefix, false)
	case utils.IsASN(normalized):
		HandleASN(ctx, rc, normalized, CacheKeyPrefix, false)
	case utils.IsDomain(normalized):
		HandleDomain(ctx, rc, normalized, CacheKeyPrefix, false, false)
	default:
		utils.HandleHTTPError(rc, utils.ErrorTypeBadRequest, "Invalid input. Please provide a valid domain, IP, or ASN.")
	}

	item.Status = rc.StatusCode()
	body := rc.Body()
	if !json.Valid(body) {
		// Defensive: every handler output on these paths is JSON today, but a
		// non-JSON body must not corrupt the batch response.
		quoted, _ := json.Marshal(string(body))
		body = quoted
	}
	if item.Status < 400 {
		item.Data = body
	} else {
		item.Error = body
	}
	return item
}
