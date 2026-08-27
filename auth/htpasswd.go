package auth

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
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
		hash := parts[1]
		if _, err := bcrypt.Cost([]byte(hash)); err != nil {
			continue
		}
		if _, exists := users[parts[0]]; exists {
			log.Printf("warning: htpasswd file contains duplicate username %q", parts[0])
		}
		users[parts[0]] = hash
		dummyHash = []byte(hash)
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

// Middleware returns a middleware that requires HTTP basic authentication
// against h, presenting realm to clients that supply none.
//
// A request that passes reaches the next handler with its authenticated
// username in the request context, readable with UsernameFromContext, so a
// handler can attribute the request without parsing the header again.
func (h *HtpasswdFile) Middleware(realm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			if !ok || !h.Check(username, password) {
				// log the client address of every 401 response so that/external tools such as fail2ban can watch for
				// and block brute-force attempts against HTTP basic auth.
				log.Printf("authentication failed: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q`, realm))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
				return
			}
			next.ServeHTTP(w, r.WithContext(ContextWithUsername(r.Context(), username)))
		})
	}
}
