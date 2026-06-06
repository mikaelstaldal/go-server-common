package httputil_test

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mikaelstaldal/go-server-common/httputil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const gzipPayload = "hello, gzip world — this is the response body"

func gzipEcho() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, gzipPayload)
	})
}

func TestGzip_CompressesWhenAccepted(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")

	httputil.Gzip(gzipEcho()).ServeHTTP(rec, req)

	res := rec.Result()
	assert.Equal(t, "gzip", res.Header.Get("Content-Encoding"))
	assert.Empty(t, res.Header.Get("Content-Length"))

	gr, err := gzip.NewReader(res.Body)
	require.NoError(t, err)
	body, err := io.ReadAll(gr)
	require.NoError(t, err)
	assert.Equal(t, gzipPayload, string(body))
}

func TestGzip_PassThroughWhenNotAccepted(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	httputil.Gzip(gzipEcho()).ServeHTTP(rec, req)

	res := rec.Result()
	assert.Empty(t, res.Header.Get("Content-Encoding"))
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, gzipPayload, string(body))
}
