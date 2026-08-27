package csrf_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mikaelstaldal/go-server-common/csrf"
	"github.com/stretchr/testify/assert"
)

func TestMiddlewareOrigins(t *testing.T) {
	const own = "http://127.0.0.1:7777"
	const allowed = "https://ui.example.com"

	reached := false
	h := csrf.MiddlewareOrigins(own, allowed)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name       string
		method     string
		origin     string
		referer    string
		wantStatus int
	}{
		{"POST from own origin", http.MethodPost, own, "", http.StatusOK},
		{"POST from an allowed origin", http.MethodPost, allowed, "", http.StatusOK},
		{"POST from an unlisted origin", http.MethodPost, "https://evil.example.com", "", http.StatusForbidden},
		{"POST with null origin", http.MethodPost, "null", "", http.StatusForbidden},
		{"POST with no headers is a native client", http.MethodPost, "", "", http.StatusOK},
		{"POST by allowed Referer", http.MethodPost, "", allowed + "/issues/1", http.StatusOK},
		{"POST by unlisted Referer", http.MethodPost, "", "https://evil.example.com/x", http.StatusForbidden},
		{"DELETE from an allowed origin", http.MethodDelete, allowed, "", http.StatusOK},
		{"PATCH from an unlisted origin", http.MethodPatch, "https://evil.example.com", "", http.StatusForbidden},

		// Safe methods are exempt; OPTIONS carries the CORS preflight and must
		// reach the handler that answers it.
		{"GET cross-origin", http.MethodGet, "https://evil.example.com", "", http.StatusOK},
		{"HEAD cross-origin", http.MethodHead, "https://evil.example.com", "", http.StatusOK},
		{"OPTIONS preflight cross-origin", http.MethodOptions, allowed, "", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached = false
			req := httptest.NewRequest(tc.method, "/api/issues", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code)
			assert.Equal(t, tc.wantStatus == http.StatusOK, reached)
			if tc.wantStatus == http.StatusForbidden {
				assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
				assert.Contains(t, rec.Body.String(), `"error"`)
			}
		})
	}
}

// Middleware is MiddlewareOrigins with one origin, so the single-origin
// behaviour the package already had is unchanged.
func TestMiddlewareIsSingleAllowedOrigin(t *testing.T) {
	const own = "https://example.com"
	h := csrf.Middleware(own)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Origin", own)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Origin", "https://other.example.com")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// A server that allows no browser origin at all still accepts native clients,
// which send neither header.
func TestMiddlewareOriginsWithNoOrigins(t *testing.T) {
	h := csrf.MiddlewareOrigins()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	assert.Equal(t, http.StatusOK, rec.Code)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Origin", "https://example.com")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}
