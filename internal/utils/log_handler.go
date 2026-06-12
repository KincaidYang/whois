package utils

import (
	"context"
	"log/slog"
)

// ContextHandler wraps a slog.Handler and appends request_id and client
// attributes to records whose context carries them (see WithRequestID and
// WithClient), so all logs emitted on a request path can be correlated and
// attributed to a caller. Log calls must use the *Context slog variants for
// the attributes to flow through.
type ContextHandler struct {
	slog.Handler
}

// NewContextHandler wraps h with request-id and client extraction.
func NewContextHandler(h slog.Handler) *ContextHandler {
	return &ContextHandler{Handler: h}
}

func (h *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if id, ok := RequestIDFromContext(ctx); ok {
		r.AddAttrs(slog.String("request_id", id))
	}
	if name, ok := ClientFromContext(ctx); ok {
		r.AddAttrs(slog.String("client", name))
	}
	return h.Handler.Handle(ctx, r)
}

func (h *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ContextHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h *ContextHandler) WithGroup(name string) slog.Handler {
	return &ContextHandler{Handler: h.Handler.WithGroup(name)}
}
