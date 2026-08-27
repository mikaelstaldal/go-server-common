package auth

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// LoadHtpasswdStrict reads an htpasswd file like LoadHtpasswd, but refuses
// anything it does not fully understand instead of skipping it.
//
// LoadHtpasswd is forgiving: it passes over a line that is not a
// "username:hash" pair and over any hash that is not bcrypt. That suits a file
// an operator shares with other tools, but it means a login the operator
// believes in may silently not exist. LoadHtpasswdStrict is for callers that
// would rather fail at startup: every non-blank line must be a
// "username:bcrypt-hash" pair, and the error names the file and the line number
// so the operator can find it. Blank lines are the only thing ignored —
// comments included, since "#" is a legal leading character for a username.
//
// validateUsername, when non-nil, is applied to each username; a username it
// rejects fails the load the same way. It exists for callers whose usernames
// become something with a vocabulary of its own, so a name the rest of the
// system could never accept is refused here rather than at first use.
func LoadHtpasswdStrict(path string, validateUsername func(username string) error) (*HtpasswdFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open htpasswd file: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only

	users := make(map[string]string)
	var dummyHash []byte
	scanner := bufio.NewScanner(f)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		username, hash, ok := strings.Cut(text, ":")
		if !ok {
			return nil, fmt.Errorf("%s line %d: not a \"username:hash\" pair", path, line)
		}
		if username == "" {
			return nil, fmt.Errorf("%s line %d: empty username", path, line)
		}
		if _, err := bcrypt.Cost([]byte(hash)); err != nil {
			return nil, fmt.Errorf("%s line %d: %q is not a bcrypt hash (use \"htpasswd -B\")", path, line, username)
		}
		if validateUsername != nil {
			if err := validateUsername(username); err != nil {
				return nil, fmt.Errorf("%s line %d: invalid username %q: %w", path, line, username, err)
			}
		}
		if _, exists := users[username]; exists {
			return nil, fmt.Errorf("%s line %d: duplicate username %q", path, line, username)
		}
		users[username] = hash
		dummyHash = []byte(hash)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read htpasswd file: %w", err)
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("%s: contains no entries", path)
	}

	return &HtpasswdFile{dummyHash: dummyHash, users: users}, nil
}
