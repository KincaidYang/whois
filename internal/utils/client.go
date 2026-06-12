package utils

import "context"

// clientKey is the context key under which the authenticated client's name is
// stored (see config.AuthClient).
type clientKey struct{}

// WithClient returns a copy of ctx carrying the authenticated client's name.
func WithClient(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, clientKey{}, name)
}

// ClientFromContext returns the authenticated client name stored in ctx, if
// any. Requests on an instance without auth enabled carry none.
func ClientFromContext(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(clientKey{}).(string)
	return name, ok && name != ""
}
