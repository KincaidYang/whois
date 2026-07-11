package handlers

import (
	"encoding/json"
	"testing"
)

// TestWithoutAnonymousSecurity verifies that patching the embedded spec drops
// exactly the anonymous alternative from the top-level security array and
// leaves the rest of the document intact.
func TestWithoutAnonymousSecurity(t *testing.T) {
	patched, err := withoutAnonymousSecurity(openAPISpec)
	if err != nil {
		t.Fatalf("withoutAnonymousSecurity(embedded spec) error: %v", err)
	}

	var doc struct {
		OpenAPI  string                       `json:"openapi"`
		Security []map[string]json.RawMessage `json:"security"`
		Paths    map[string]json.RawMessage   `json:"paths"`
	}
	if err := json.Unmarshal(patched, &doc); err != nil {
		t.Fatalf("patched spec is not valid JSON: %v", err)
	}

	if len(doc.Security) == 0 {
		t.Fatal("patched spec has no security requirements left")
	}
	for i, alternative := range doc.Security {
		if len(alternative) == 0 {
			t.Errorf("security[%d] is still the anonymous alternative", i)
		}
	}
	names := make(map[string]bool)
	for _, alternative := range doc.Security {
		for name := range alternative {
			names[name] = true
		}
	}
	if !names["bearerAuth"] || !names["apiKeyHeader"] {
		t.Errorf("patched security lost a scheme: got %v, want bearerAuth and apiKeyHeader", names)
	}

	var orig struct {
		OpenAPI string                     `json:"openapi"`
		Paths   map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(openAPISpec, &orig); err != nil {
		t.Fatalf("embedded spec is not valid JSON: %v", err)
	}
	if doc.OpenAPI != orig.OpenAPI {
		t.Errorf("openapi version changed: %q -> %q", orig.OpenAPI, doc.OpenAPI)
	}
	if len(doc.Paths) != len(orig.Paths) {
		t.Errorf("paths changed: %d -> %d entries", len(orig.Paths), len(doc.Paths))
	}

	// A spec with no anonymous alternative must be reported, not silently
	// left as-is: the guard exists so a future edit to openapi.json that
	// removes the anonymous entry (or renames security) fails loudly.
	if _, err := withoutAnonymousSecurity(patched); err == nil {
		t.Error("patching a spec without an anonymous alternative should error")
	}
}
