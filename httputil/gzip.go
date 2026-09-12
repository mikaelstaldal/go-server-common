package httputil

import (
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

type gzipResponseWriter struct {
	http.ResponseWriter
	writer      *gzip.Writer
	disabled    bool
	compressed  bool
	wroteHeader bool
}

func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	if !g.wroteHeader {
		g.wroteHeader = true
		g.prepare()
	}
	if g.disabled {
		return g.ResponseWriter.Write(b)
	}
	return g.writer.Write(b)
}

func (g *gzipResponseWriter) WriteHeader(statusCode int) {
	if g.wroteHeader {
		g.ResponseWriter.WriteHeader(statusCode)
		return
	}
	if statusCode >= 100 && statusCode < 200 && statusCode != http.StatusSwitchingProtocols {
		g.ResponseWriter.WriteHeader(statusCode)
		return
	}
	g.wroteHeader = true
	if statusCode == http.StatusSwitchingProtocols || statusCode == http.StatusNoContent || statusCode == http.StatusNotModified {
		g.disabled = true
		g.Header().Del("Content-Encoding")
	} else {
		g.prepare()
	}
	g.ResponseWriter.WriteHeader(statusCode)
}

func (g *gzipResponseWriter) prepare() {
	if g.Header().Get("Content-Encoding") != "" {
		g.disabled = true
		return
	}
	g.compressed = true
	g.Header().Set("Content-Encoding", "gzip")
	g.Header().Del("Content-Length")
}

var gzipWriterPool = sync.Pool{
	New: func() any {
		return gzip.NewWriter(io.Discard)
	},
}

func acceptsGzip(header http.Header) bool {
	gzipSeen := false
	gzipQuality := 0.0
	wildcardQuality := 0.0

	for _, value := range header.Values("Accept-Encoding") {
		for coding := range strings.SplitSeq(value, ",") {
			parts := strings.Split(coding, ";")
			name := strings.ToLower(strings.TrimSpace(parts[0]))
			if name != "gzip" && name != "*" {
				continue
			}
			quality := 1.0
			valid := true
			for _, parameter := range parts[1:] {
				key, value, found := strings.Cut(parameter, "=")
				if !found || !strings.EqualFold(strings.TrimSpace(key), "q") {
					continue
				}
				var err error
				quality, err = strconv.ParseFloat(strings.TrimSpace(value), 64)
				if err != nil {
					quality = 1
				}
				valid = quality >= 0 && quality <= 1
				break
			}
			if !valid {
				continue
			}

			if name == "gzip" {
				gzipSeen = true
				gzipQuality = max(gzipQuality, quality)
			} else {
				wildcardQuality = max(wildcardQuality, quality)
			}
		}
	}

	if gzipSeen {
		return gzipQuality > 0
	}
	return wildcardQuality > 0
}

// Gzip returns a middleware that gzip-compresses the response body when the
// client advertises gzip support via the Accept-Encoding request header.
// Requests without gzip support and responses whose status forbids a body are
// passed through uncompressed.
func Gzip(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Accept-Encoding")
		if !acceptsGzip(r.Header) || r.Header.Get("Range") != "" {
			next.ServeHTTP(w, r)
			return
		}
		gz := gzipWriterPool.Get().(*gzip.Writer)
		gz.Reset(w)
		gw := &gzipResponseWriter{ResponseWriter: w, writer: gz}
		defer func() {
			if gw.compressed {
				_ = gz.Close()
			}
			gz.Reset(io.Discard)
			gzipWriterPool.Put(gz)
		}()
		next.ServeHTTP(gw, r)
	})
}
