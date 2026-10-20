package httputil_test

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/mikaelstaldal/go-server-common/httputil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSpecialPurposeAddressesBlockedAcrossFetchPaths(t *testing.T) {
	for _, host := range []string{
		"0.1.2.3", "10.0.0.1", "100.64.0.0", "100.100.100.200", "100.127.255.255",
		"127.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.1.1",
		"192.0.0.1", "192.0.2.1", "192.88.99.1", "198.18.0.1", "198.19.255.255",
		"198.51.100.1", "203.0.113.1", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::10.0.0.1", "::ffff:0:10.0.0.1", "::ffff:100.100.100.200", "::ffff:127.0.0.1",
		"64:ff9b::a00:1", "64:ff9b:1::1", "100::1", "100:0:0:1::1",
		"2001::1", "2001:2::1", "2001:db8::1", "2002:a00:1::1", "3fff::1",
		"2001:1ff:ffff::1", "4000::1", "fc00::1", "fe80::1", "fec0::1", "5f00::1", "ff02::1",
	} {
		t.Run(host, func(t *testing.T) {
			require.True(t, httputil.IsBlockedIP(net.ParseIP(host)))
			rawURL := "http://" + net.JoinHostPort(host, "80") + "/resource"
			require.ErrorContains(t, httputil.ValidateExternalURL(rawURL), "private or local")
			req, err := http.NewRequest(http.MethodGet, rawURL, nil)
			require.NoError(t, err)
			require.ErrorContains(t, httputil.SafeCheckRedirect(10)(req, nil), "private or local")

			// A canceled context ensures this test never opens a network connection.
			// The policy error must precede the dialer's context-canceled error.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			conn, err := httputil.SafeDialContext(&net.Dialer{})(ctx, "tcp", net.JoinHostPort(host, "80"))
			assert.Nil(t, conn)
			require.ErrorContains(t, err, "private or local")

			client := httputil.NewSafeHTTPClient(time.Second)
			defer client.CloseIdleConnections()
			req = req.WithContext(context.Background())
			resp, err := client.Do(req)
			assert.Nil(t, resp)
			require.ErrorContains(t, err, "private or local")
		})
	}
}

func TestPublicAddressesAllowed(t *testing.T) {
	for _, host := range []string{
		"1.1.1.1", "8.8.8.8", "100.63.255.255", "100.128.0.0",
		"198.17.255.255", "198.20.0.0", "::ffff:8.8.8.8", "2606:4700:4700::1111",
		"2001:4860:4860::8888", "2001:200::1", "3fff:1000::1", "2003::1",
	} {
		t.Run(host, func(t *testing.T) {
			assert.False(t, httputil.IsBlockedIP(net.ParseIP(host)))
			require.NoError(t, httputil.ValidateExternalURL("https://"+net.JoinHostPort(host, "443")))
		})
	}
	assert.True(t, httputil.IsBlockedIP(nil))
	assert.True(t, httputil.IsBlockedIP(net.IP{1, 2, 3}))
}
