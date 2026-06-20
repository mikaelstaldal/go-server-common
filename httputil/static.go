package httputil

import (
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"net/http"
	"strings"
)

// StaticHandler serves the files in fsys with gzip compression and ETag-based
// revalidation, suitable for assets embedded via embed.FS.
//
// An embed.FS exposes neither a modtime nor an ETag, so http.FileServer emits no
// validator. Without one, "Cache-Control: no-cache" (revalidate before use) can
// never be satisfied and every request re-downloads the full body. StaticHandler
// precomputes a content hash per file — embedded files are immutable for the
// process lifetime — and answers "304 Not Modified" when the client's
// If-None-Match matches. The 304 is handled before the gzip wrapper, so empty
// not-modified responses are never gzip-encoded.
//
// It walks fsys once up front to build the ETag table; pass the sub-filesystem
// you intend to serve (e.g. via fs.Sub).
func StaticHandler(fsys fs.FS) (http.Handler, error) {
	etags := make(map[string]string)
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		etags["/"+p] = `"` + base64.RawURLEncoding.EncodeToString(sum[:]) + `"`
		return nil
	})
	if err != nil {
		return nil, err
	}

	fileServer := Gzip(http.FileServer(http.FS(fsys)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		if etag, ok := etags[r.URL.Path]; ok {
			w.Header().Set("ETag", etag)
			w.Header().Add("Vary", "Accept-Encoding")
			if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		fileServer.ServeHTTP(w, r)
	}), nil
}
