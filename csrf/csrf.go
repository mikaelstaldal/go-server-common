package csrf

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
)

// Middleware returns a middleware that rejects unsafe requests whose origin
// does not match serverOrigin (e.g. "https://mail.example.com"). Requests
// with neither Origin nor Referer are allowed (native clients).
// "Origin: null" is always rejected.
//
// It is MiddlewareOrigins with a single acceptable origin.
func Middleware(serverOrigin string) func(http.Handler) http.Handler {
	return MiddlewareOrigins(serverOrigin)
}

// MiddlewareOrigins is Middleware accepting any of several origins, for a
// server that deliberately allows browser clients hosted elsewhere — the same
// set an API would name in its CORS configuration. Its own origin is just one
// more entry in that list.
//
// The safe methods GET, HEAD and OPTIONS are exempt: they are not state
// changing, and OPTIONS in particular carries the CORS preflight, which must
// reach the handler that answers it.
func MiddlewareOrigins(allowedOrigins ...string) func(http.Handler) http.Handler {
	allowed := slices.Clone(allowedOrigins)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSafeMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			if err := checkCSRFOrigin(r, allowed); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func checkCSRFOrigin(r *http.Request, allowedOrigins []string) error {
	origin := r.Header.Get("Origin")

	if origin == "" {
		referer := r.Header.Get("Referer")
		if referer == "" {
			return nil // native client, allow
		}
		u, err := url.Parse(referer)
		if err != nil || u.Host == "" {
			return fmt.Errorf("CSRF: invalid Referer header")
		}
		origin = u.Scheme + "://" + u.Host
	}

	if origin == "null" {
		return fmt.Errorf("CSRF: null origin rejected")
	}

	if !slices.Contains(allowedOrigins, origin) {
		return fmt.Errorf("CSRF: origin %q is not allowed", origin)
	}
	return nil
}
