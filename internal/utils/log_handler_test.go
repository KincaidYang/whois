package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// logLine emits one Info record through logger and decodes the JSON output.
func logLine(t *testing.T, buf *bytes.Buffer, logger *slog.Logger, ctx context.Context) map[string]any {
	t.Helper()
	buf.Reset()
	logger.InfoContext(ctx, "msg")
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("log output is not JSON: %v (%q)", err, buf.String())
	}
	return m
}

func TestContextHandlerAddsRequestAttributes(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewContextHandler(slog.NewJSONHandler(&buf, nil)))

	ctx := WithClient(WithRequestID(context.Background(), "req-123"), "acme")
	m := logLine(t, &buf, logger, ctx)
	if m["request_id"] != "req-123" {
		t.Errorf("request_id = %v, want req-123", m["request_id"])
	}
	if m["client"] != "acme" {
		t.Errorf("client = %v, want acme", m["client"])
	}

	// A bare context must not produce empty correlation attributes.
	m = logLine(t, &buf, logger, context.Background())
	if _, ok := m["request_id"]; ok {
		t.Error("request_id present without one in the context")
	}
}

func TestContextHandlerWithAttrsKeepsExtraction(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewContextHandler(slog.NewJSONHandler(&buf, nil)))

	// WithAttrs must return a ContextHandler, not the bare inner handler —
	// otherwise request-id extraction silently stops after logger.With().
	derived := logger.With("component", "test")
	ctx := WithRequestID(context.Background(), "req-456")
	m := logLine(t, &buf, derived, ctx)
	if m["component"] != "test" {
		t.Errorf("component = %v, want test", m["component"])
	}
	if m["request_id"] != "req-456" {
		t.Errorf("request_id = %v, want req-456 after With()", m["request_id"])
	}
}

func TestContextHandlerWithGroupKeepsExtraction(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewContextHandler(slog.NewJSONHandler(&buf, nil)))

	derived := logger.WithGroup("grp")
	ctx := WithRequestID(context.Background(), "req-789")
	buf.Reset()
	derived.InfoContext(ctx, "msg")
	// The record attr lands inside the open group; asserting on the raw JSON
	// avoids coupling the test to slog's group nesting layout.
	if !strings.Contains(buf.String(), "req-789") {
		t.Errorf("output %q lost the request id after WithGroup()", buf.String())
	}
}
