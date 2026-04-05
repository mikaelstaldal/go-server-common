package csrf

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// Middleware rejects state-changing requests (POST, PUT, PATCH, DELETE)
// whose Origin (or origin derived from Referer) does not match the server's
// own origin. Requests with neither header are assumed to be native clients
// and are allowed through. "Origin: null" is always rejected.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isStateChangingMethod(r.Method) {
			if err := checkCSRFOrigin(r); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isStateChangingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

func checkCSRFOrigin(r *http.Request) error {
	origin := r.Header.Get("Origin")

	if origin == "" {
		referer := r.Header.Get("Referer")
		if referer == "" {
			// No header present — native client, allow.
			return nil
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

	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return fmt.Errorf("CSRF: invalid Origin header")
	}
	originHost := u.Host

	serverHost := serverHostFromRequest(r)

	if originHost != serverHost {
		return fmt.Errorf("CSRF: origin host %q does not match server host %q", originHost, serverHost)
	}
	return nil
}

// serverHostFromRequest returns the server's public-facing host (hostname:port
// or just hostname when using a standard port). X-Forwarded-Host takes
// precedence to handle TLS-terminating reverse proxies where r.Host is the
// internal address. The scheme is intentionally not compared: the
// scheme difference between the browser's https and the proxy's internal http
// is a TLS-termination artefact, not a meaningful CSRF boundary.
func serverHostFromRequest(r *http.Request) string {
	if host := r.Header.Get("X-Forwarded-Host"); host != "" {
		return host
	}
	return r.Host
}
