// Package devicegrant implements RFC 8628 with SQLite-backed, single-use grants.
// Authentication, CSRF protection and Host policy are the mounting application's responsibility.
package devicegrant

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const GrantType = "urn:ietf:params:oauth:grant-type:device_code"
const alphabet = "BCDFGHJKLMNPQRSTVWXZ"

// ErrInvalidGrant tells ValidateScope that a resource no longer exists. On an
// approved poll this permanently consumes the grant without minting a token.
var ErrInvalidGrant = errors.New("device grant is no longer valid")

// DDL is immutable schema version 1. Future versions must expose separate
// migration statements; applications embed this in their historical migrations.
// It belongs in the application's versioned migrations, not in request handling.
const DDL = `CREATE TABLE device_authorizations (
 device_code_hash BLOB PRIMARY KEY NOT NULL,
 user_code TEXT UNIQUE NOT NULL,
 client_id TEXT NOT NULL,
 name TEXT NOT NULL,
 requested_scope TEXT NOT NULL,
 requested_lifetime TEXT NOT NULL,
 requester TEXT NOT NULL,
 created_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 last_poll_at TEXT NOT NULL DEFAULT '',
 interval INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','denied')),
 granted_scope TEXT NOT NULL DEFAULT '',
 granted_expiry TEXT NOT NULL DEFAULT ''
)`

type Authorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

type Request struct {
	UserCode  string   `json:"user_code"`
	ClientID  string   `json:"client_id"`
	Name      string   `json:"name"`
	Scope     []string `json:"scope"`
	Lifetime  string   `json:"lifetime"`
	Requester string   `json:"requester"`
	CreatedAt string   `json:"created_at"`
	ExpiresAt string   `json:"expires_at"`
}

type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
	// Slug is an extension used by token management CLIs for revocation.
	Slug string `json:"slug,omitempty"`
}

type Server struct {
	DB              *sql.DB
	ClientIDs       []string
	VerificationURI string
	// ValidateScope checks app-specific syntax and resource existence using tx.
	ValidateScope func(context.Context, *sql.Tx, []string) error
	// AllowEmptyScope permits unscoped consent when ValidateScope accepts an
	// empty slice. False preserves the requirement to select at least one scope.
	AllowEmptyScope bool
	// Mint must write through tx only. Its changes and consuming the grant commit together.
	Mint            func(context.Context, *sql.Tx, string, []string, time.Time) (Token, error)
	TTL             time.Duration
	Interval        time.Duration
	MaxPending      int
	MaxPerRequester int
	// Now is optional; primarily useful for deterministic testing.
	Now func() time.Time
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC().Truncate(time.Second)
	}
	return time.Now().UTC().Truncate(time.Second)
}
func (s *Server) allowed(id string) bool {
	for _, v := range s.ClientIDs {
		if v == id {
			return true
		}
	}
	return false
}

var lifetimeRE = regexp.MustCompile(`^([1-9][0-9]*)([smhd])$`)

// ParseLifetime accepts the token CLI's duration syntax, bounded at ten years.
func ParseLifetime(value string) (time.Duration, error) {
	m := lifetimeRE.FindStringSubmatch(value)
	if m == nil {
		return 0, errors.New("invalid lifetime")
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	unit := map[string]int64{"s": 1, "m": 60, "h": 3600, "d": 86400}[m[2]]
	if err != nil || n > 315360000/unit {
		return 0, errors.New("invalid lifetime")
	}
	return time.Duration(n*unit) * time.Second, nil
}

// NormalizeUserCode accepts case- and hyphen-insensitive input only.
func NormalizeUserCode(code string) (string, bool) {
	for _, c := range code {
		if c > 127 {
			return "", false
		}
	}
	code = strings.ToUpper(strings.ReplaceAll(code, "-", ""))
	if len(code) != 8 {
		return "", false
	}
	for _, c := range code {
		if !strings.ContainsRune(alphabet, c) {
			return "", false
		}
	}
	return code[:4] + "-" + code[4:], true
}
func write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
func failure(w http.ResponseWriter, status int, code string) {
	write(w, status, map[string]string{"error": code})
}
func form(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		failure(w, 405, "invalid_request")
		return false
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		failure(w, 400, "invalid_request")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if r.ParseForm() != nil {
		failure(w, 400, "invalid_request")
		return false
	}
	for _, vals := range r.PostForm {
		if len(vals) != 1 {
			failure(w, 400, "invalid_request")
			return false
		}
	}
	return true
}

func (s *Server) Authorize(w http.ResponseWriter, r *http.Request) {
	uri, err := url.Parse(s.VerificationURI)
	if err != nil || uri.Scheme == "" || uri.Host == "" || s.ValidateScope == nil || s.Mint == nil {
		failure(w, 500, "server_error")
		return
	}
	if !form(w, r) {
		return
	}
	id, name, scope, lifetime := r.PostForm.Get("client_id"), r.PostForm.Get("name"), r.PostForm.Get("scope"), r.PostForm.Get("lifetime")
	if !s.allowed(id) {
		failure(w, 400, "invalid_client")
		return
	}
	if strings.TrimSpace(name) == "" || len(name) > 200 || !utf8.ValidString(name) || strings.IndexFunc(name, func(c rune) bool { return unicode.IsControl(c) || unicode.Is(unicode.Cf, c) }) >= 0 || len(scope) > 4096 {
		failure(w, 400, "invalid_request")
		return
	}
	if lifetime == "" {
		lifetime = "30d"
	}
	if _, err := ParseLifetime(lifetime); err != nil {
		failure(w, 400, "invalid_request")
		return
	}
	tx, err := s.DB.BeginTx(r.Context(), nil)
	if err != nil {
		failure(w, 500, "server_error")
		return
	}
	defer tx.Rollback()
	now := s.now()
	if _, err = tx.ExecContext(r.Context(), `DELETE FROM device_authorizations WHERE expires_at <= ?`, now.Format(time.RFC3339)); err != nil {
		failure(w, 500, "server_error")
		return
	}
	var count int
	if err = tx.QueryRowContext(r.Context(), `SELECT count(*) FROM device_authorizations`).Scan(&count); err != nil {
		failure(w, 500, "server_error")
		return
	}
	maxPending := s.MaxPending
	if maxPending <= 0 {
		maxPending = 10
	}
	if count >= maxPending {
		failure(w, 429, "temporarily_unavailable")
		return
	}
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		ip = r.RemoteAddr
	}
	perRequester := s.MaxPerRequester
	if perRequester <= 0 {
		perRequester = 3
	}
	if err = tx.QueryRowContext(r.Context(), `SELECT count(*) FROM device_authorizations WHERE substr(requester,1,instr(requester,' | ')-1)=?`, ip).Scan(&count); err != nil {
		failure(w, 500, "server_error")
		return
	}
	if count >= perRequester {
		failure(w, 429, "temporarily_unavailable")
		return
	}
	scopes := strings.Fields(scope)
	if len(scopes) > 0 && s.ValidateScope(r.Context(), tx, scopes) != nil {
		failure(w, 400, "invalid_scope")
		return
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		failure(w, 500, "server_error")
		return
	}
	device := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(device))
	var code strings.Builder
	for range 8 {
		n, e := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if e != nil {
			failure(w, 500, "server_error")
			return
		}
		code.WriteByte(alphabet[n.Int64()])
	}
	user, _ := NormalizeUserCode(code.String())
	ttl := s.TTL
	if ttl < time.Second {
		ttl = 600 * time.Second
	}
	interval := s.Interval
	if interval < time.Second {
		interval = 5 * time.Second
	}
	// Do not trust forwarded IP headers. The app's trusted proxy middleware may set RemoteAddr.
	agent := strings.Map(func(c rune) rune {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			return -1
		}
		return c
	}, strings.ToValidUTF8(r.UserAgent(), ""))
	for len(agent) > 512 {
		_, size := utf8.DecodeLastRuneInString(agent)
		agent = agent[:len(agent)-size]
	}
	requester := ip + " | " + agent
	_, err = tx.ExecContext(r.Context(), `INSERT INTO device_authorizations(device_code_hash,user_code,client_id,name,requested_scope,requested_lifetime,requester,created_at,expires_at,interval) VALUES(?,?,?,?,?,?,?,?,?,?)`, hash[:], user, id, strings.TrimSpace(name), strings.Join(scopes, " "), lifetime, requester, now.Format(time.RFC3339), now.Add(ttl).Format(time.RFC3339), int64(interval/time.Second))
	if err != nil || tx.Commit() != nil {
		failure(w, 500, "server_error")
		return
	}
	q := uri.Query()
	q.Set("user_code", user)
	uri.RawQuery = q.Encode()
	write(w, 200, Authorization{device, user, s.VerificationURI, uri.String(), int64(ttl / time.Second), int64(interval / time.Second)})
}

func (s *Server) Poll(w http.ResponseWriter, r *http.Request) {
	if !form(w, r) {
		return
	}
	if !s.allowed(r.PostForm.Get("client_id")) {
		failure(w, 400, "invalid_client")
		return
	}
	if r.PostForm.Get("grant_type") != GrantType {
		failure(w, 400, "unsupported_grant_type")
		return
	}
	device := r.PostForm.Get("device_code")
	if device == "" {
		failure(w, 400, "invalid_request")
		return
	}
	hash := sha256.Sum256([]byte(device))
	tx, err := s.DB.BeginTx(r.Context(), nil)
	if err != nil {
		failure(w, 500, "server_error")
		return
	}
	defer tx.Rollback()
	// Acquire the SQLite write lock before reading, including across app processes.
	if _, err = tx.ExecContext(r.Context(), `UPDATE device_authorizations SET interval=interval WHERE device_code_hash=?`, hash[:]); err != nil {
		failure(w, 500, "server_error")
		return
	}
	var id, name, expires, last, status, scope, expiry string
	var interval int64
	err = tx.QueryRowContext(r.Context(), `SELECT client_id,name,expires_at,last_poll_at,interval,status,granted_scope,granted_expiry FROM device_authorizations WHERE device_code_hash=?`, hash[:]).Scan(&id, &name, &expires, &last, &interval, &status, &scope, &expiry)
	if errors.Is(err, sql.ErrNoRows) || err == nil && id != r.PostForm.Get("client_id") {
		failure(w, 400, "invalid_grant")
		return
	}
	if err != nil {
		failure(w, 500, "server_error")
		return
	}
	now := s.now()
	until, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		failure(w, 500, "server_error")
		return
	}
	if !now.Before(until) {
		failure(w, 400, "expired_token")
		return
	}
	if last != "" {
		previous, e := time.Parse(time.RFC3339, last)
		if e != nil {
			failure(w, 500, "server_error")
			return
		}
		if now.Sub(previous) < time.Duration(interval)*time.Second {
			_, err = tx.ExecContext(r.Context(), `UPDATE device_authorizations SET interval=interval+5,last_poll_at=? WHERE device_code_hash=?`, now.Format(time.RFC3339), hash[:])
			if err != nil || tx.Commit() != nil {
				failure(w, 500, "server_error")
				return
			}
			failure(w, 400, "slow_down")
			return
		}
	}
	if status == "denied" {
		if _, err = tx.ExecContext(r.Context(), `DELETE FROM device_authorizations WHERE device_code_hash=?`, hash[:]); err != nil || tx.Commit() != nil {
			failure(w, 500, "server_error")
			return
		}
		failure(w, 400, "access_denied")
		return
	}
	if status == "pending" {
		_, err = tx.ExecContext(r.Context(), `UPDATE device_authorizations SET last_poll_at=? WHERE device_code_hash=?`, now.Format(time.RFC3339), hash[:])
		if err != nil || tx.Commit() != nil {
			failure(w, 500, "server_error")
			return
		}
		failure(w, 400, "authorization_pending")
		return
	}
	until, err = time.Parse(time.RFC3339, expiry)
	if err != nil {
		failure(w, 500, "server_error")
		return
	}
	if !now.Before(until) {
		failure(w, 400, "expired_token")
		return
	}
	if s.ValidateScope == nil {
		failure(w, 500, "server_error")
		return
	}
	if err = s.ValidateScope(r.Context(), tx, strings.Fields(scope)); err != nil {
		if errors.Is(err, ErrInvalidGrant) {
			if _, err = tx.ExecContext(r.Context(), `DELETE FROM device_authorizations WHERE device_code_hash=?`, hash[:]); err != nil || tx.Commit() != nil {
				failure(w, 500, "server_error")
				return
			}
			failure(w, 400, "invalid_grant")
			return
		}
		failure(w, 500, "server_error")
		return
	}
	if s.Mint == nil {
		failure(w, 500, "server_error")
		return
	}
	token, err := s.Mint(r.Context(), tx, name, strings.Fields(scope), until)
	if err != nil {
		failure(w, 500, "server_error")
		return
	}
	if _, err = tx.ExecContext(r.Context(), `DELETE FROM device_authorizations WHERE device_code_hash=?`, hash[:]); err != nil {
		failure(w, 500, "server_error")
		return
	}
	if tx.Commit() != nil {
		failure(w, 500, "server_error")
		return
	}
	token.TokenType = "Bearer"
	token.Scope = scope
	token.ExpiresIn = int64(until.Sub(now) / time.Second)
	write(w, 200, token)
}

// Approval must be mounted behind full-access auth and CSRF, never bearer auth.
func (s *Server) Approval(w http.ResponseWriter, r *http.Request) {
	code, ok := NormalizeUserCode(r.PathValue("user_code"))
	if !ok {
		failure(w, 404, "not_found")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		failure(w, 405, "invalid_request")
		return
	}
	var input struct {
		Approve  *bool    `json:"approve"`
		Scope    []string `json:"scope"`
		Lifetime string   `json:"lifetime"`
	}
	if r.Method == http.MethodPost {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			failure(w, 400, "invalid_request")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if dec.Decode(&input) != nil || input.Approve == nil || dec.Decode(new(any)) != io.EOF {
			failure(w, 400, "invalid_request")
			return
		}
	}
	tx, err := s.DB.BeginTx(r.Context(), nil)
	if err != nil {
		failure(w, 500, "server_error")
		return
	}
	defer tx.Rollback()
	if r.Method == http.MethodPost {
		if _, err = tx.ExecContext(r.Context(), `UPDATE device_authorizations SET interval=interval WHERE user_code=?`, code); err != nil {
			failure(w, 500, "server_error")
			return
		}
	}
	var req Request
	var scope string
	now := s.now()
	err = tx.QueryRowContext(r.Context(), `SELECT user_code,client_id,name,requested_scope,requested_lifetime,requester,created_at,expires_at FROM device_authorizations WHERE user_code=? AND status='pending' AND expires_at>?`, code, now.Format(time.RFC3339)).Scan(&req.UserCode, &req.ClientID, &req.Name, &scope, &req.Lifetime, &req.Requester, &req.CreatedAt, &req.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		failure(w, 404, "not_found")
		return
	}
	if err != nil {
		failure(w, 500, "server_error")
		return
	}
	req.Scope = strings.Fields(scope)
	if req.Scope == nil {
		req.Scope = []string{}
	}
	if r.Method == http.MethodGet {
		write(w, 200, req)
		return
	}
	status, granted, expiry := "denied", "", ""
	if *input.Approve {
		duration, e := ParseLifetime(input.Lifetime)
		if e != nil || (len(input.Scope) == 0 && !s.AllowEmptyScope) || s.ValidateScope == nil || s.ValidateScope(r.Context(), tx, input.Scope) != nil {
			failure(w, 400, "invalid_request")
			return
		}
		status = "approved"
		granted = strings.Join(input.Scope, " ")
		expiry = now.Add(duration).Format(time.RFC3339)
	}
	_, err = tx.ExecContext(r.Context(), `UPDATE device_authorizations SET status=?,granted_scope=?,granted_expiry=? WHERE user_code=?`, status, granted, expiry, code)
	if err != nil || tx.Commit() != nil {
		failure(w, 500, "server_error")
		return
	}
	write(w, 200, map[string]bool{"approved": *input.Approve})
}
