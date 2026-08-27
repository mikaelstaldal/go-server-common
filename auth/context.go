package auth

import "context"

type usernameContextKey struct{}

// ContextWithUsername returns a copy of ctx carrying the authenticated
// username. Middleware installs it on every request it lets through.
func ContextWithUsername(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, usernameContextKey{}, username)
}

// UsernameFromContext returns the authenticated username Middleware recorded on
// the request, and whether there was one. A handler reached without the
// middleware in front of it gets ("", false).
func UsernameFromContext(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(usernameContextKey{}).(string)
	return username, ok
}
