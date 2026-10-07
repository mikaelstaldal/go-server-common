package hostguard_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mikaelstaldal/go-server-common/csrf"
	"github.com/mikaelstaldal/go-server-common/hostguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware(t *testing.T) {
	p, err := hostguard.New("https://PUBLIC.example:8443/app", "127.0.0.2", 8080)
	require.NoError(t, err)
	for _, host := range []string{"localhost:8080", "LOCALHOST:08080", "127.0.0.1:8080", "127.0.0.2:8080", "[::1]:8080", "[0:0:0:0:0:0:0:1]:8080", "public.example:8443"} {
		t.Run(host, func(t *testing.T) { checkHost(t, p, host, http.MethodPost, http.StatusNoContent) })
	}
	for _, host := range []string{"attacker.example:8080", "localhost", "localhost:8081", "public.example", "public.example:443", "127.0.0.3:8080", "0.0.0.0:8080", "", "localhost:", "localhost:0", "localhost:65536", "localhost:+8080", "localhost:bad", "localhost:8080/path", "localhost:8080?x", "localhost:8080#x", "user@localhost:8080", "localhost:8080,public.example", " localhost:8080", "localhost:8080\t", "localhost:8080\x7f", "localhost:8080\\x", "local%68ost:8080", "::1:8080", "[localhost]:8080", "[::1%lo]:8080", "[::1]:", "[::1]extra", "localhost.:8080", "-localhost:8080", "local_host:8080"} {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost, http.MethodPut, http.MethodDelete} {
			t.Run(host+method, func(t *testing.T) { checkHost(t, p, host, method, http.StatusMisdirectedRequest) })
		}
	}
}

func checkHost(t *testing.T, p *hostguard.Policy, host, method string, want int) {
	t.Helper()
	called := false
	h := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(method, "/", nil)
	r.Host = host
	r.Header.Set("Host", "public.example:8443")
	r.Header.Set("X-Forwarded-Host", "public.example:8443")
	r.Header.Set("Forwarded", "host=public.example:8443;proto=https")
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(t, want, w.Code)
	assert.Equal(t, want == http.StatusNoContent, called)
	if want == http.StatusMisdirectedRequest {
		assert.JSONEq(t, `{"error":"invalid host"}`, w.Body.String())
	}
}

func TestDefaultPortsAndIPv6(t *testing.T) {
	for _, public := range []string{"http://example.com", "http://EXAMPLE.com:80", "https://example.com", "https://example.com:443"} {
		p, err := hostguard.New(public, "::1", 80)
		require.NoError(t, err)
		checkHost(t, p, "example.com", http.MethodGet, http.StatusNoContent)
		if public[:5] == "https" {
			checkHost(t, p, "example.com:443", http.MethodGet, http.StatusNoContent)
			checkHost(t, p, "example.com:80", http.MethodGet, http.StatusMisdirectedRequest)
		} else {
			checkHost(t, p, "example.com:80", http.MethodGet, http.StatusNoContent)
		}
		checkHost(t, p, "localhost", http.MethodGet, http.StatusNoContent)
	}
	p, err := hostguard.New("https://[2001:db8::1]", "::", 8080)
	require.NoError(t, err)
	checkHost(t, p, "[2001:0db8:0:0:0:0:0:1]:443", http.MethodGet, http.StatusNoContent)
	checkHost(t, p, "[2001:db8::1]", http.MethodGet, http.StatusNoContent)
	checkHost(t, p, "[::]:8080", http.MethodGet, http.StatusMisdirectedRequest)
}

func TestConfiguration(t *testing.T) {
	for _, tt := range []struct {
		public, addr string
		port         int
	}{
		{"", "", 8080}, {"", "0.0.0.0", 8080}, {"", "::", 8080}, {"", "::ffff:0.0.0.0", 8080},
		{"", "localhost", 0}, {"", "localhost", 65536},
		{"ftp://example.com", "localhost", 8080}, {"//example.com", "localhost", 8080},
		{"https://user:password@example.com", "localhost", 8080},
		{"https://example.com:", "localhost", 8080}, {"https://example.com:bad", "localhost", 8080},
		{"https://example.com:0", "localhost", 8080}, {"https://[example.com]", "localhost", 8080},
		{"https://example.com.", "localhost", 8080}, {"http://", "localhost", 8080},
		{"", "[::1]", 8080}, {"", "localhost:8080", 8080}, {"", "bad host", 8080}, {"", "fe80::1%lo", 8080},
	} {
		t.Run(tt.public+tt.addr, func(t *testing.T) {
			p, err := hostguard.New(tt.public, tt.addr, tt.port)
			require.Error(t, err)
			assert.Nil(t, p)
		})
	}
	for _, addr := range []string{"", "0.0.0.0", "::", "localhost", "192.0.2.1"} {
		_, err := hostguard.New("https://example.com:8443", addr, 8080)
		require.NoError(t, err)
	}
}

func TestOriginsWithCSRF(t *testing.T) {
	for _, tt := range []struct {
		public, addr string
		port         int
	}{
		{"https://PUBLIC.example:443/path", "127.0.0.2", 80},
		{"https://public.example:8443", "::", 8080},
		{"https://[2001:0db8::1]", "::1", 8080},
		{"", "localhost", 443},
		{"https://[::ffff:192.0.2.1]", "::1", 8080},
	} {
		p, err := hostguard.New(tt.public, tt.addr, tt.port)
		require.NoError(t, err)
		origins := p.Origins()
		require.NotEmpty(t, origins)
		originals := append([]string(nil), origins...)
		origins[0] = "http://attacker.example"
		assert.Equal(t, originals, p.Origins())
		h := p.Middleware(csrf.MiddlewareOrigins(p.Origins()...)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })))
		for _, origin := range originals {
			r := httptest.NewRequest(http.MethodPost, origin+"/write", nil)
			r.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			assert.Equal(t, http.StatusNoContent, w.Code, origin)
			r.Header.Set("Origin", "http://attacker.example")
			w = httptest.NewRecorder()
			h.ServeHTTP(w, r)
			assert.Equal(t, http.StatusForbidden, w.Code, origin)
		}
	}
}
