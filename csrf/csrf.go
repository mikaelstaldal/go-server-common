package csrf

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// Middleware returns a middleware that rejects non-GET requests whose origin
// does not match serverOrigin (e.g. "https://mail.example.com"). Requests
// with neither Origin nor Referer are allowed (native clients).
// "Origin: null" is always rejected.
func Middleware(serverOrigin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				next.ServeHTTP(w, r)
				return
			}
			if err := checkCSRFOrigin(r, serverOrigin); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func checkCSRFOrigin(r *http.Request, serverOrigin string) error {
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

	if origin != serverOrigin {
		return fmt.Errorf("CSRF: origin %q does not match server origin", origin)
	}
	return nil
}
