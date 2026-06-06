package httputil_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mikaelstaldal/go-server-common/httputil"
	"github.com/stretchr/testify/assert"
)

func serve(t *testing.T, opts httputil.SecurityHeadersOptions) http.Header {
	t.Helper()
	h := httputil.SecurityHeaders(opts)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec.Result().Header
}

func TestSecurityHeaders_SetsBaseHeaders(t *testing.T) {
	hdr := serve(t, httputil.SecurityHeadersOptions{CSP: "default-src 'self'"})

	assert.Equal(t, "nosniff", hdr.Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", hdr.Get("X-Frame-Options"))
	assert.Equal(t, "default-src 'self'", hdr.Get("Content-Security-Policy"))
}

func TestSecurityHeaders_DefaultReferrerPolicy(t *testing.T) {
	hdr := serve(t, httputil.SecurityHeadersOptions{CSP: "default-src 'self'"})
	assert.Equal(t, "strict-origin-when-cross-origin", hdr.Get("Referrer-Policy"))
}

func TestSecurityHeaders_CustomReferrerPolicy(t *testing.T) {
	hdr := serve(t, httputil.SecurityHeadersOptions{CSP: "default-src 'self'", ReferrerPolicy: "same-origin"})
	assert.Equal(t, "same-origin", hdr.Get("Referrer-Policy"))
}

func TestSecurityHeaders_HSTSOmittedWhenEmpty(t *testing.T) {
	hdr := serve(t, httputil.SecurityHeadersOptions{CSP: "default-src 'self'"})
	assert.Empty(t, hdr.Get("Strict-Transport-Security"))
}

func TestSecurityHeaders_HSTSSetWhenProvided(t *testing.T) {
	hdr := serve(t, httputil.SecurityHeadersOptions{CSP: "default-src 'self'", HSTS: "max-age=31536000; includeSubDomains"})
	assert.Equal(t, "max-age=31536000; includeSubDomains", hdr.Get("Strict-Transport-Security"))
}
