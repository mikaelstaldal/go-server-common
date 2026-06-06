package csrf_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mikaelstaldal/go-server-common/csrf"
	"github.com/stretchr/testify/assert"
)

func TestCSRFMiddleware(t *testing.T) {
	const serverOrigin = "http://example.com"

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := csrf.Middleware(serverOrigin)(okHandler)

	cases := []struct {
		name       string
		method     string
		origin     string
		referer    string
		wantStatus int
	}{
		// GET is always exempt
		{
			name:       "GET no headers",
			method:     http.MethodGet,
			wantStatus: http.StatusOK,
		},
		{
			name:       "GET cross-origin",
			method:     http.MethodGet,
			origin:     "https://evil.example.com",
			wantStatus: http.StatusOK,
		},

		// No Origin/Referer → native client, allow
		{
			name:       "POST no headers",
			method:     http.MethodPost,
			wantStatus: http.StatusOK,
		},
		{
			name:       "DELETE no headers",
			method:     http.MethodDelete,
			wantStatus: http.StatusOK,
		},

		// Origin: null always rejected
		{
			name:       "POST null origin",
			method:     http.MethodPost,
			origin:     "null",
			wantStatus: http.StatusForbidden,
		},

		// Matching origin allowed
		{
			name:       "POST same origin",
			method:     http.MethodPost,
			origin:     serverOrigin,
			wantStatus: http.StatusOK,
		},
		{
			name:       "PUT same origin",
			method:     http.MethodPut,
			origin:     serverOrigin,
			wantStatus: http.StatusOK,
		},
		{
			name:       "PATCH same origin",
			method:     http.MethodPatch,
			origin:     serverOrigin,
			wantStatus: http.StatusOK,
		},
		{
			name:       "DELETE same origin",
			method:     http.MethodDelete,
			origin:     serverOrigin,
			wantStatus: http.StatusOK,
		},

		// Cross-origin rejected
		{
			name:       "POST cross-origin",
			method:     http.MethodPost,
			origin:     "https://evil.example.com",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "DELETE cross-origin port mismatch",
			method:     http.MethodDelete,
			origin:     "http://example.com:9999",
			wantStatus: http.StatusForbidden,
		},

		// Referer fallback — same origin allowed
		{
			name:       "POST same referer no origin",
			method:     http.MethodPost,
			referer:    "http://example.com/some/page",
			wantStatus: http.StatusOK,
		},

		// Referer fallback — cross-origin rejected
		{
			name:       "POST cross-origin referer",
			method:     http.MethodPost,
			referer:    "https://evil.example.com/page",
			wantStatus: http.StatusForbidden,
		},

		// Origin header takes precedence over Referer
		{
			name:       "POST same origin with cross-origin referer",
			method:     http.MethodPost,
			origin:     serverOrigin,
			referer:    "https://evil.example.com/page",
			wantStatus: http.StatusOK,
		},

		// Malformed Referer rejected
		{
			name:       "POST malformed referer",
			method:     http.MethodPost,
			referer:    "not-a-url",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/v1/events", strings.NewReader("{}"))
			req.Host = "example.com"
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			assert.Equal(t, tc.wantStatus, rr.Code)
		})
	}
}
