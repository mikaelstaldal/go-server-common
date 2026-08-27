package auth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mikaelstaldal/go-server-common/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bcrypt hash of "secret", cost 10.
const bcryptSecret = "$2a$10$g6h.kOLcUo4A7Yg9X1hPGeCJT523p2.6xNk9Yldg2iyqz2F7U2o9e"

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "htpasswd")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestLoadHtpasswdStrictAcceptsBcryptAndBlankLines(t *testing.T) {
	path := writeFile(t, "\nalice:"+bcryptSecret+"\n\nbob:"+bcryptSecret+"\n\n")

	h, err := auth.LoadHtpasswdStrict(path, nil)
	require.NoError(t, err)
	assert.True(t, h.Check("alice", "secret"))
	assert.True(t, h.Check("bob", "secret"))
	assert.False(t, h.Check("alice", "wrong"))
	assert.False(t, h.Check("carol", "secret"))
}

func TestLoadHtpasswdStrictRejects(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantIn  string
	}{
		{"no colon", "alice\n", "line 1"},
		{"empty username", ":" + bcryptSecret + "\n", "empty username"},
		{"md5 hash", "alice:$apr1$abcdefgh$0123456789012345678901\n", "not a bcrypt hash"},
		{"sha1 hash", "alice:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\n", "not a bcrypt hash"},
		{"crypt hash", "alice:aBcDeFgHiJkLm\n", "not a bcrypt hash"},
		{"comment is not ignored", "#alice:x\n", "not a bcrypt hash"},
		{"bad line after good one", "alice:" + bcryptSecret + "\nbob\n", "line 2"},
		{"duplicate username", "alice:" + bcryptSecret + "\nalice:" + bcryptSecret + "\n", "duplicate"},
		{"empty file", "\n\n", "contains no entries"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := auth.LoadHtpasswdStrict(writeFile(t, tc.content), nil)
			require.Error(t, err, "nothing may be skipped silently")
			assert.Contains(t, err.Error(), tc.wantIn)
		})
	}
}

func TestLoadHtpasswdStrictNamesTheFile(t *testing.T) {
	path := writeFile(t, "alice\n")
	_, err := auth.LoadHtpasswdStrict(path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), path)
}

func TestLoadHtpasswdStrictValidatesUsernames(t *testing.T) {
	errBad := errors.New("must be lowercase")
	validate := func(u string) error {
		if u != "alice" {
			return errBad
		}
		return nil
	}

	_, err := auth.LoadHtpasswdStrict(writeFile(t, "alice:"+bcryptSecret+"\n"), validate)
	require.NoError(t, err)

	_, err = auth.LoadHtpasswdStrict(writeFile(t, "Alice:"+bcryptSecret+"\n"), validate)
	require.Error(t, err)
	assert.ErrorIs(t, err, errBad)
	assert.Contains(t, err.Error(), `invalid username "Alice"`)
}

func TestLoadHtpasswdStrictMissingFile(t *testing.T) {
	_, err := auth.LoadHtpasswdStrict(filepath.Join(t.TempDir(), "nope"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open htpasswd file")
}

func TestMiddlewarePassesUsernameToHandler(t *testing.T) {
	h, err := auth.LoadHtpasswdStrict(writeFile(t, "alice:"+bcryptSecret+"\n"), nil)
	require.NoError(t, err)

	var got string
	var ok bool
	handler := h.Middleware("test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok = auth.UsernameFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("alice", "secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, ok)
	assert.Equal(t, "alice", got)
}

func TestMiddlewareUnauthorizedIsJSON(t *testing.T) {
	h, err := auth.LoadHtpasswdStrict(writeFile(t, "alice:"+bcryptSecret+"\n"), nil)
	require.NoError(t, err)

	handler := h.Middleware("myrealm")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not be reached")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, `Basic realm="myrealm"`, rec.Header().Get("WWW-Authenticate"))
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.JSONEq(t, `{"error":"unauthorized"}`, rec.Body.String())
}

func TestUsernameFromContextWithoutMiddleware(t *testing.T) {
	username, ok := auth.UsernameFromContext(t.Context())
	assert.False(t, ok)
	assert.Empty(t, username)
}
