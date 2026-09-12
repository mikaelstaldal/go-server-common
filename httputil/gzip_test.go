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
	assert.Contains(t, res.Header.Values("Vary"), "Accept-Encoding")

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
	assert.Contains(t, res.Header.Values("Vary"), "Accept-Encoding")
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, gzipPayload, string(body))
}

func TestGzip_HonorsAcceptEncodingQuality(t *testing.T) {
	tests := []struct {
		name           string
		acceptEncoding string
		compressed     bool
	}{
		{name: "positive quality", acceptEncoding: "br, gzip;q=0.5", compressed: true},
		{name: "zero quality", acceptEncoding: "br, gzip;q=0", compressed: false},
		{name: "case insensitive", acceptEncoding: "GZip; Q=1", compressed: true},
		{name: "wildcard", acceptEncoding: "br, *;q=0.5", compressed: true},
		{name: "explicit zero overrides wildcard", acceptEncoding: "gzip;q=0, *;q=1", compressed: false},
		{name: "malformed quality uses default", acceptEncoding: "gzip;q=abc", compressed: true},
		{name: "invalid gzip quality allows wildcard", acceptEncoding: "gzip;q=5, *;q=1", compressed: true},
		{name: "not a coding substring", acceptEncoding: "x-gzipish", compressed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Accept-Encoding", tt.acceptEncoding)

			httputil.Gzip(gzipEcho()).ServeHTTP(rec, req)

			assert.Equal(t, tt.compressed, rec.Header().Get("Content-Encoding") == "gzip")
		})
	}
}

func TestGzip_StripsHandlerContentLength(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, gzipPayload)
	})

	httputil.Gzip(handler).ServeHTTP(rec, req)

	assert.Empty(t, rec.Header().Get("Content-Length"))
}

func TestGzip_PreservesHandlerContentEncoding(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "br")
		_, _ = io.WriteString(w, gzipPayload)
	})

	httputil.Gzip(handler).ServeHTTP(rec, req)

	assert.Equal(t, "br", rec.Header().Get("Content-Encoding"))
	assert.Equal(t, gzipPayload, rec.Body.String())
}

func TestGzip_PassesThroughRangeRequest(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Range", "bytes=0-9")

	httputil.Gzip(gzipEcho()).ServeHTTP(rec, req)

	assert.Empty(t, rec.Header().Get("Content-Encoding"))
	assert.Equal(t, gzipPayload, rec.Body.String())
}

func TestGzip_DoesNotCompressBodylessStatus(t *testing.T) {
	for _, statusCode := range []int{http.StatusNoContent, http.StatusNotModified} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Accept-Encoding", "gzip")
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(statusCode)
			})

			httputil.Gzip(handler).ServeHTTP(rec, req)

			assert.Equal(t, statusCode, rec.Code)
			assert.Empty(t, rec.Header().Get("Content-Encoding"))
			assert.Empty(t, rec.Body.Bytes())
		})
	}
}

func TestGzip_ReusesWriters(t *testing.T) {
	handler := httputil.Gzip(gzipEcho())
	for range 50 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")

		handler.ServeHTTP(rec, req)

		gr, err := gzip.NewReader(rec.Body)
		require.NoError(t, err)
		body, err := io.ReadAll(gr)
		require.NoError(t, err)
		require.NoError(t, gr.Close())
		assert.Equal(t, gzipPayload, string(body))
	}
}

func BenchmarkGzip(b *testing.B) {
	handler := httputil.Gzip(gzipEcho())
	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		handler.ServeHTTP(rec, req)
	}
}
