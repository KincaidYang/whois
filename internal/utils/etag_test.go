package utils

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestETagFor(t *testing.T) {
	a := ETagFor([]byte("hello"))
	b := ETagFor([]byte("hello"))
	c := ETagFor([]byte("world"))

	if a != b {
		t.Errorf("same body produced different tags: %q vs %q", a, b)
	}
	if a == c {
		t.Errorf("different bodies produced the same tag: %q", a)
	}
	if !strings.HasPrefix(a, `"`) || !strings.HasSuffix(a, `"`) {
		t.Errorf("etag not quoted: %q", a)
	}
}

func TestETagMatches(t *testing.T) {
	etag := `"abc123"`
	cases := []struct {
		ifNoneMatch string
		want        bool
	}{
		{"", false},
		{`"abc123"`, true},
		{`"other"`, false},
		{"*", true},
		{`"first", "abc123"`, true},
		{`"first", "second"`, false},
		{`W/"abc123"`, true}, // weak comparison ignores the W/ prefix
		{`abc123`, false},    // unquoted token is not the same opaque tag
	}
	for _, c := range cases {
		if got := ETagMatches(c.ifNoneMatch, etag); got != c.want {
			t.Errorf("ETagMatches(%q, %q) = %v, want %v", c.ifNoneMatch, etag, got, c.want)
		}
	}
}

func TestConditionalWriter200(t *testing.T) {
	rec := httptest.NewRecorder()
	cw := NewConditionalWriter(rec, "")
	cw.Header().Set("Content-Type", "application/json")
	_, _ = cw.Write([]byte(`{"a":1}`))
	if code := cw.Finish(); code != http.StatusOK {
		t.Fatalf("Finish: got %d, want 200", code)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d", rec.Code)
	}
	if rec.Body.String() != `{"a":1}` {
		t.Errorf("body: %q", rec.Body.String())
	}
	if rec.Header().Get("ETag") != ETagFor([]byte(`{"a":1}`)) {
		t.Errorf("ETag: %q", rec.Header().Get("ETag"))
	}
}

func TestConditionalWriterNotModified(t *testing.T) {
	body := []byte(`{"a":1}`)
	rec := httptest.NewRecorder()
	cw := NewConditionalWriter(rec, ETagFor(body))
	cw.Header().Set("Content-Type", "application/json")
	_, _ = cw.Write(body)
	if code := cw.Finish(); code != http.StatusNotModified {
		t.Fatalf("Finish: got %d, want 304", code)
	}

	if rec.Code != http.StatusNotModified {
		t.Errorf("status: got %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("304 carried a body: %q", rec.Body.String())
	}
	if rec.Header().Get("ETag") != ETagFor(body) {
		t.Errorf("ETag: %q", rec.Header().Get("ETag"))
	}
	if ct := rec.Header().Get("Content-Type"); ct != "" {
		t.Errorf("304 carried Content-Type: %q", ct)
	}
}

// TestConditionalWriterPassthrough verifies non-200 responses are not
// buffered and carry no ETag, even when the client sent If-None-Match.
func TestConditionalWriterPassthrough(t *testing.T) {
	rec := httptest.NewRecorder()
	cw := NewConditionalWriter(rec, "*")
	cw.WriteHeader(http.StatusNotFound)
	_, _ = cw.Write([]byte("missing"))
	if code := cw.Finish(); code != http.StatusNotFound {
		t.Fatalf("Finish: got %d, want 404", code)
	}

	if rec.Code != http.StatusNotFound {
		t.Errorf("status: got %d", rec.Code)
	}
	if rec.Body.String() != "missing" {
		t.Errorf("body: %q", rec.Body.String())
	}
	if etag := rec.Header().Get("ETag"); etag != "" {
		t.Errorf("error response carried an ETag: %q", etag)
	}
}
