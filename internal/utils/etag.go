package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// ETagFor returns a strong entity tag for body: a quoted, truncated SHA-256
// digest. The same body always yields the same tag, so tags stay valid across
// instances and restarts (cache entries are shared via Redis).
func ETagFor(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// ETagMatches reports whether the If-None-Match header value matches etag,
// using the weak comparison RFC 9110 section 13.1.2 prescribes for
// If-None-Match: W/ prefixes are ignored and "*" matches any entity.
func ETagMatches(ifNoneMatch, etag string) bool {
	if ifNoneMatch == "" {
		return false
	}
	if strings.TrimSpace(ifNoneMatch) == "*" {
		return true
	}
	target := strings.TrimPrefix(etag, "W/")
	for _, candidate := range strings.Split(ifNoneMatch, ",") {
		candidate = strings.TrimPrefix(strings.TrimSpace(candidate), "W/")
		if candidate == target {
			return true
		}
	}
	return false
}

// ConditionalWriter buffers a 200 response so an ETag can be computed over
// the complete body and compared against the request's If-None-Match header;
// a match turns the response into 304 Not Modified with no body. Responses
// with any other status code pass through untouched and carry no ETag.
// Callers must call Finish after the handler returns.
type ConditionalWriter struct {
	http.ResponseWriter
	ifNoneMatch string
	buf         bytes.Buffer
	code        int
	passthrough bool
	wroteHeader bool
}

// NewConditionalWriter wraps w for a request that sent the given
// If-None-Match header value (empty when absent).
func NewConditionalWriter(w http.ResponseWriter, ifNoneMatch string) *ConditionalWriter {
	return &ConditionalWriter{ResponseWriter: w, ifNoneMatch: ifNoneMatch, code: http.StatusOK}
}

func (cw *ConditionalWriter) WriteHeader(code int) {
	if cw.wroteHeader {
		return
	}
	cw.wroteHeader = true
	cw.code = code
	if code != http.StatusOK {
		cw.passthrough = true
		cw.ResponseWriter.WriteHeader(code)
	}
}

func (cw *ConditionalWriter) Write(b []byte) (int, error) {
	if !cw.wroteHeader {
		cw.WriteHeader(http.StatusOK)
	}
	if cw.passthrough {
		return cw.ResponseWriter.Write(b)
	}
	return cw.buf.Write(b)
}

// Finish completes the response: for buffered 200s it sets the ETag header
// and either replays the body or answers 304. It returns the status code that
// actually went out, for metrics.
func (cw *ConditionalWriter) Finish() int {
	if cw.passthrough {
		return cw.code
	}
	etag := ETagFor(cw.buf.Bytes())
	cw.Header().Set("ETag", etag)
	if ETagMatches(cw.ifNoneMatch, etag) {
		// A 304 carries no body, so the buffered Content-Type would only
		// mislead (RFC 9110 section 15.4.5).
		cw.Header().Del("Content-Type")
		cw.ResponseWriter.WriteHeader(http.StatusNotModified)
		return http.StatusNotModified
	}
	cw.ResponseWriter.WriteHeader(http.StatusOK)
	_, _ = cw.ResponseWriter.Write(cw.buf.Bytes())
	return http.StatusOK
}
