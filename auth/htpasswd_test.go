package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func hashPassword(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(hash)
}

func writeTempHtpasswd(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "htpasswd")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadHtpasswd(t *testing.T) {
	hash := hashPassword(t, "secret")
	path := writeTempHtpasswd(t, "admin:"+hash+"\n")

	htpasswd, err := LoadHtpasswd(path)
	if err != nil {
		t.Fatal(err)
	}
	if !htpasswd.Check("admin", "secret") {
		t.Error("expected valid credentials to pass")
	}
	if htpasswd.Check("admin", "wrong") {
		t.Error("expected wrong password to fail")
	}
	if htpasswd.Check("nobody", "secret") {
		t.Error("expected unknown user to fail")
	}
}

func TestLoadHtpasswd_SkipsCommentsAndBlanks(t *testing.T) {
	hash := hashPassword(t, "pass")
	content := "# comment\n\nuser:" + hash + "\n"
	path := writeTempHtpasswd(t, content)

	htpasswd, err := LoadHtpasswd(path)
	if err != nil {
		t.Fatal(err)
	}
	if !htpasswd.Check("user", "pass") {
		t.Error("expected valid credentials to pass")
	}
}

func TestLoadHtpasswd_EmptyFile(t *testing.T) {
	path := writeTempHtpasswd(t, "# only comments\n")
	_, err := LoadHtpasswd(path)
	if err == nil {
		t.Error("expected error for empty htpasswd file")
	}
}

func TestLoadHtpasswd_MissingFile(t *testing.T) {
	_, err := LoadHtpasswd("/nonexistent/htpasswd")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestMiddleware(t *testing.T) {
	hash := hashPassword(t, "secret")
	path := writeTempHtpasswd(t, "admin:"+hash+"\n")

	htpasswd, err := LoadHtpasswd(path)
	if err != nil {
		t.Fatal(err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := htpasswd.Middleware("mycal")(inner)

	t.Run("no credentials", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rec.Code)
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Error("expected WWW-Authenticate header")
		}
	})

	t.Run("valid credentials", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.SetBasicAuth("admin", "secret")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.SetBasicAuth("admin", "wrong")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rec.Code)
		}
	})
}
