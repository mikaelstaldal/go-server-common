package auth

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type HtpasswdFile struct {
	users     map[string]string // username -> bcrypt hash
	dummyHash []byte
}

func LoadHtpasswd(path string) (*HtpasswdFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open htpasswd file: %w", err)
	}
	defer f.Close()

	users := make(map[string]string)
	var dummyHash []byte
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		users[parts[0]] = parts[1]
		dummyHash = []byte(parts[1])
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read htpasswd file: %w", err)
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("htpasswd file contains no valid entries")
	}

	return &HtpasswdFile{dummyHash: dummyHash, users: users}, nil
}

func (h *HtpasswdFile) Check(username, password string) bool {
	hash, ok := h.users[username]
	if !ok {
		_ = bcrypt.CompareHashAndPassword(h.dummyHash, []byte(password)) // avoid timing attacks
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func (h *HtpasswdFile) Middleware(realm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			if !ok || !h.Check(username, password) {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q`, realm))
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
