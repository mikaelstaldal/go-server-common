package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func hashPassword(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)
	return string(hash)
}

func writeTempHtpasswd(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "htpasswd")
	err := os.WriteFile(path, []byte(content), 0600)
	require.NoError(t, err)
	return path
}

func TestLoadHtpasswd(t *testing.T) {
	hash := hashPassword(t, "secret")
	path := writeTempHtpasswd(t, "admin:"+hash+"\n")

	htpasswd, err := LoadHtpasswd(path)
	require.NoError(t, err)
	assert.True(t, htpasswd.Check("admin", "secret"), "expected valid credentials to pass")
	assert.False(t, htpasswd.Check("admin", "wrong"), "expected wrong password to fail")
	assert.False(t, htpasswd.Check("nobody", "secret"), "expected unknown user to fail")
}

func TestLoadHtpasswd_SkipsCommentsAndBlanks(t *testing.T) {
	hash := hashPassword(t, "pass")
	content := "# comment\n\nuser:" + hash + "\n"
	path := writeTempHtpasswd(t, content)

	htpasswd, err := LoadHtpasswd(path)
	require.NoError(t, err)
	assert.True(t, htpasswd.Check("user", "pass"), "expected valid credentials to pass")
}

func TestLoadHtpasswd_EmptyFile(t *testing.T) {
	path := writeTempHtpasswd(t, "# only comments\n")
	_, err := LoadHtpasswd(path)
	assert.Error(t, err, "expected error for empty htpasswd file")
}

func TestLoadHtpasswd_MissingFile(t *testing.T) {
	_, err := LoadHtpasswd("/nonexistent/htpasswd")
	assert.Error(t, err, "expected error for missing file")
}

func TestMiddleware(t *testing.T) {
	hash := hashPassword(t, "secret")
	path := writeTempHtpasswd(t, "admin:"+hash+"\n")

	htpasswd, err := LoadHtpasswd(path)
	require.NoError(t, err)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := htpasswd.Middleware("mycal")(inner)

	t.Run("no credentials", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.NotEmpty(t, rec.Header().Get("WWW-Authenticate"), "expected WWW-Authenticate header")
	})

	t.Run("valid credentials", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.SetBasicAuth("admin", "secret")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("wrong password", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.SetBasicAuth("admin", "wrong")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}
