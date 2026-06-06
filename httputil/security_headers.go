// Package httputil provides reusable HTTP middleware for servers.
package httputil

import "net/http"

// SecurityHeadersOptions configures the SecurityHeaders middleware.
type SecurityHeadersOptions struct {
	// CSP is the Content-Security-Policy header value. Required.
	CSP string
	// ReferrerPolicy is the Referrer-Policy header value. Defaults to
	// "strict-origin-when-cross-origin" when empty.
	ReferrerPolicy string
	// HSTS is the Strict-Transport-Security header value. When empty the header
	// is omitted (e.g. for plain-HTTP deployments). A typical value when served
	// over HTTPS is "max-age=31536000; includeSubDomains".
	HSTS string
}

// SecurityHeaders returns a middleware that sets a standard set of security
// headers on every response: X-Content-Type-Options, X-Frame-Options,
// Referrer-Policy, Content-Security-Policy, and optionally
// Strict-Transport-Security.
func SecurityHeaders(opts SecurityHeadersOptions) func(http.Handler) http.Handler {
	referrerPolicy := opts.ReferrerPolicy
	if referrerPolicy == "" {
		referrerPolicy = "strict-origin-when-cross-origin"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", referrerPolicy)
			h.Set("Content-Security-Policy", opts.CSP)
			if opts.HSTS != "" {
				h.Set("Strict-Transport-Security", opts.HSTS)
			}
			next.ServeHTTP(w, r)
		})
	}
}
