package httputil_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mikaelstaldal/go-server-common/httputil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{"127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "169.254.1.1", "0.0.0.0"}
	for _, s := range blocked {
		assert.True(t, httputil.IsBlockedIP(net.ParseIP(s)), "expected %s to be blocked", s)
	}

	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34"}
	for _, s := range allowed {
		assert.False(t, httputil.IsBlockedIP(net.ParseIP(s)), "expected %s to be allowed", s)
	}
}

func TestValidateExternalURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid https", "https://example.com/path", false},
		{"valid http", "http://example.com/path", false},
		{"invalid scheme", "ftp://example.com/path", true},
		{"no hostname", "http:///path", true},
		{"localhost", "http://localhost/path", true},
		{"localhost subdomain", "http://foo.localhost/path", true},
		{"loopback IP", "http://127.0.0.1/path", true},
		{"private IP", "http://192.168.1.1/path", true},
		{"link-local IP", "http://169.254.169.254/path", true},
		{"malformed URL", "http://[::1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := httputil.ValidateExternalURL(tt.url)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewSafeHTTPClient_BlocksLoopbackTarget(t *testing.T) {
	server := httptest.NewServer(nil)
	defer server.Close()

	client := httputil.NewSafeHTTPClient(2 * 1e9) // 2 seconds

	resp, err := client.Get(server.URL)
	if err == nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err, "expected request to a loopback address to be blocked")
}

func TestSafeCheckRedirect_StopsAfterMaxRedirects(t *testing.T) {
	checkRedirect := httputil.SafeCheckRedirect(2)

	req := httptest.NewRequest("GET", "https://example.com/", nil)
	err := checkRedirect(req, []*http.Request{{}, {}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "stopped after 2 redirects")
}
