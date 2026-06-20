package httputil

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStaticHandler(t *testing.T) http.Handler {
	t.Helper()
	fsys := fstest.MapFS{
		"app.js": {Data: []byte("console.log('hello world');\n")},
	}
	h, err := StaticHandler(fsys)
	require.NoError(t, err)
	return h
}

func TestStaticHandler_ServesETagAndRevalidates(t *testing.T) {
	h := newTestStaticHandler(t)

	// First request: full body with an ETag and revalidation directive.
	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "no-cache", rec.Header().Get("Cache-Control"))
	etag := rec.Header().Get("ETag")
	require.NotEmpty(t, etag, "embedded asset must carry an ETag for revalidation")
	assert.NotEmpty(t, rec.Body.Bytes())

	// Second request with matching If-None-Match: 304, no body, gzip not applied.
	req2 := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	req2.Header.Set("If-None-Match", etag)
	req2.Header.Set("Accept-Encoding", "gzip")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)

	assert.Equal(t, http.StatusNotModified, rec2.Code)
	assert.Equal(t, etag, rec2.Header().Get("ETag"))
	assert.Empty(t, rec2.Body.Bytes(), "304 must not carry a body")
	assert.Empty(t, rec2.Header().Get("Content-Encoding"), "304 must not be gzip-encoded")
}

func TestStaticHandler_GzipsFullResponses(t *testing.T) {
	h := newTestStaticHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "gzip", rec.Header().Get("Content-Encoding"))
	assert.Contains(t, rec.Header().Values("Vary"), "Accept-Encoding")

	gr, err := gzip.NewReader(rec.Body)
	require.NoError(t, err)
	body, err := io.ReadAll(gr)
	require.NoError(t, err)
	assert.Equal(t, "console.log('hello world');\n", string(body))
}

func TestStaticHandler_DistinctEtagsPerFile(t *testing.T) {
	fsys := fstest.MapFS{
		"app.js":  {Data: []byte("a")},
		"app.css": {Data: []byte("b")},
	}
	h, err := StaticHandler(fsys)
	require.NoError(t, err)

	get := func(path string) string {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Header().Get("ETag")
	}
	assert.NotEqual(t, get("/app.js"), get("/app.css"))
}
