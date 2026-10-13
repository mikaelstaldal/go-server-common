package devicegrant

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mikaelstaldal/go-server-common/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setup(t *testing.T) (*Server, *time.Time) {
	t.Helper()
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "test.db"), 5000, [][]string{{DDL, `CREATE TABLE minted (secret TEXT)`}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &Server{DB: db, ClientIDs: []string{"test"}, VerificationURI: "https://example.org/cal/?settings=tokens", Now: func() time.Time { return now }}
	s.ValidateScope = func(ctx context.Context, tx *sql.Tx, scopes []string) error {
		if len(scopes) != 1 || scopes[0] != "calendar:0" {
			return errors.New("bad scope")
		}
		return nil
	}
	s.Mint = func(ctx context.Context, tx *sql.Tx, name string, scopes []string, expiry time.Time) (Token, error) {
		_, err := tx.ExecContext(ctx, `INSERT INTO minted VALUES ('secret')`)
		return Token{AccessToken: "secret", Slug: "test"}, err
	}
	return s, &now
}
func postForm(handler http.HandlerFunc, values url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "test CLI")
	r.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}
func start(t *testing.T, s *Server) Authorization {
	t.Helper()
	w := postForm(s.Authorize, url.Values{"client_id": {"test"}, "name": {"Test"}, "scope": {"calendar:0"}, "lifetime": {"30d"}})
	require.Equal(t, 200, w.Code, w.Body.String())
	var a Authorization
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &a))
	return a
}
func poll(s *Server, code string) *httptest.ResponseRecorder {
	return postForm(s.Poll, url.Values{"client_id": {"test"}, "device_code": {code}, "grant_type": {GrantType}})
}
func approve(s *Server, code, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("user_code", code)
	w := httptest.NewRecorder()
	s.Approval(w, r)
	return w
}
func TestHappyPathAndSingleUse(t *testing.T) {
	s, now := setup(t)
	a := start(t, s)
	assert.Equal(t, int64(600), a.ExpiresIn)
	assert.Equal(t, int64(5), a.Interval)
	assert.Contains(t, a.VerificationURIComplete, "user_code=")
	r := httptest.NewRequest("GET", "/", nil)
	r.SetPathValue("user_code", strings.ToLower(strings.ReplaceAll(a.UserCode, "-", "")))
	w := httptest.NewRecorder()
	s.Approval(w, r)
	require.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "127.0.0.1 | test CLI")
	assert.Contains(t, poll(s, a.DeviceCode).Body.String(), "authorization_pending")
	require.Equal(t, 200, approve(s, a.UserCode, `{"approve":true,"scope":["calendar:0"],"lifetime":"30d"}`).Code)
	*now = now.Add(5 * time.Second)
	w = poll(s, a.DeviceCode)
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"access_token":"secret"`)
	assert.Contains(t, poll(s, a.DeviceCode).Body.String(), "invalid_grant")
	var count int
	require.NoError(t, s.DB.QueryRow(`SELECT count(*) FROM minted`).Scan(&count))
	assert.Equal(t, 1, count)
	var raw []byte
	err := s.DB.QueryRow(`SELECT device_code_hash FROM device_authorizations`).Scan(&raw)
	assert.ErrorIs(t, err, sql.ErrNoRows)
}
func TestPollingErrors(t *testing.T) {
	for _, test := range []struct {
		name, code string
		modify     func(*Server, *time.Time, Authorization)
	}{
		{"pending", "authorization_pending", func(*Server, *time.Time, Authorization) {}},
		{"denied", "access_denied", func(s *Server, _ *time.Time, a Authorization) {
			require.Equal(t, 200, approve(s, a.UserCode, `{"approve":false}`).Code)
		}},
		{"expired", "expired_token", func(_ *Server, n *time.Time, _ Authorization) { *n = n.Add(600 * time.Second) }},
		{"unknown", "invalid_grant", func(s *Server, _ *time.Time, _ Authorization) {
			_, err := s.DB.Exec(`DELETE FROM device_authorizations`)
			require.NoError(t, err)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, n := setup(t)
			a := start(t, s)
			test.modify(s, n, a)
			w := poll(s, a.DeviceCode)
			assert.Equal(t, 400, w.Code)
			assert.Contains(t, w.Body.String(), test.code)
		})
	}
	s, now := setup(t)
	a := start(t, s)
	poll(s, a.DeviceCode)
	assert.Contains(t, poll(s, a.DeviceCode).Body.String(), "slow_down")
	*now = now.Add(5 * time.Second)
	assert.Contains(t, poll(s, a.DeviceCode).Body.String(), "slow_down")
	var interval int
	require.NoError(t, s.DB.QueryRow(`SELECT interval FROM device_authorizations`).Scan(&interval))
	assert.Equal(t, 15, interval)
	*now = now.Add(15 * time.Second)
	assert.Contains(t, poll(s, a.DeviceCode).Body.String(), "authorization_pending")
}
func TestMalformedRequests(t *testing.T) {
	s, _ := setup(t)
	for _, test := range []struct {
		handler http.HandlerFunc
		values  url.Values
		code    string
	}{
		{s.Authorize, url.Values{"client_id": {"wrong"}}, "invalid_client"},
		{s.Authorize, url.Values{"client_id": {"test"}}, "invalid_request"},
		{s.Authorize, url.Values{"client_id": {"test"}, "name": {"x"}, "scope": {"bad"}}, "invalid_scope"},
		{s.Authorize, url.Values{"client_id": {"test"}, "name": {"x"}, "lifetime": {"999999999999999999d"}}, "invalid_request"},
		{s.Poll, url.Values{"client_id": {"wrong"}}, "invalid_client"},
		{s.Poll, url.Values{"client_id": {"test"}, "grant_type": {"bad"}}, "unsupported_grant_type"},
		{s.Poll, url.Values{"client_id": {"test"}, "grant_type": {GrantType}}, "invalid_request"},
		{s.Poll, url.Values{"client_id": {"test", "test"}}, "invalid_request"},
	} {
		w := postForm(test.handler, test.values)
		assert.Equal(t, 400, w.Code)
		assert.Contains(t, w.Body.String(), test.code)
	}
	a := start(t, s)
	for _, body := range []string{`{}`, `{"approve":true,"scope":["bad"],"lifetime":"30d"}`, `{"approve":true,"scope":[],"lifetime":"30d"}`, `{"approve":false} {}`} {
		assert.Equal(t, 400, approve(s, a.UserCode, body).Code)
	}
}
func TestCapCleanupAndHashOnly(t *testing.T) {
	s, now := setup(t)
	s.MaxPending = 1
	a := start(t, s)
	assert.Equal(t, 429, postForm(s.Authorize, url.Values{"client_id": {"test"}, "name": {"Test"}}).Code)
	var hash []byte
	require.NoError(t, s.DB.QueryRow(`SELECT device_code_hash FROM device_authorizations`).Scan(&hash))
	assert.Len(t, hash, 32)
	assert.NotEqual(t, []byte(a.DeviceCode), hash)
	*now = now.Add(600 * time.Second)
	start(t, s)
}
func TestMintFailureRollsBack(t *testing.T) {
	s, _ := setup(t)
	a := start(t, s)
	require.Equal(t, 200, approve(s, a.UserCode, `{"approve":true,"scope":["calendar:0"],"lifetime":"30d"}`).Code)
	mint := s.Mint
	s.Mint = func(ctx context.Context, tx *sql.Tx, n string, scope []string, e time.Time) (Token, error) {
		_, err := mint(ctx, tx, n, scope, e)
		require.NoError(t, err)
		return Token{}, errors.New("failure")
	}
	assert.Equal(t, 500, poll(s, a.DeviceCode).Code)
	var count int
	require.NoError(t, s.DB.QueryRow(`SELECT count(*) FROM minted`).Scan(&count))
	assert.Zero(t, count)
	require.NoError(t, s.DB.QueryRow(`SELECT count(*) FROM device_authorizations`).Scan(&count))
	assert.Equal(t, 1, count)
	s.Mint = mint
	assert.Equal(t, 200, poll(s, a.DeviceCode).Code)
}
func TestNormalizationAndLifetime(t *testing.T) {
	for _, value := range []string{"bcdfghjk", "bcdf-ghjk", "BCDF-GHJK"} {
		code, ok := NormalizeUserCode(value)
		assert.True(t, ok)
		assert.Equal(t, "BCDF-GHJK", code)
	}
	for _, value := range []string{"abcd-efgh", "BCDFGHJ", " BCDFGHJK", "BCDFGHJK\n"} {
		_, ok := NormalizeUserCode(value)
		assert.False(t, ok)
	}
	d, err := ParseLifetime("30d")
	require.NoError(t, err)
	assert.Equal(t, 720*time.Hour, d)
}

func TestApprovalAndConfigurationGuards(t *testing.T) {
	s, now := setup(t)
	valid := s.VerificationURI
	s.VerificationURI = "%bad"
	assert.Equal(t, 500, postForm(s.Authorize, url.Values{"client_id": {"test"}, "name": {"Test"}}).Code)
	var count int
	require.NoError(t, s.DB.QueryRow(`SELECT count(*) FROM device_authorizations`).Scan(&count))
	assert.Zero(t, count)
	s.VerificationURI = valid
	assert.Equal(t, 400, postForm(s.Authorize, url.Values{"client_id": {"test"}, "name": {"Test\u202e"}}).Code)
	a := start(t, s)
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"approve":false}`))
	r.Header.Set("Content-Type", "text/plain")
	r.SetPathValue("user_code", a.UserCode)
	w := httptest.NewRecorder()
	s.Approval(w, r)
	assert.Equal(t, 400, w.Code)
	require.Equal(t, 200, approve(s, a.UserCode, `{"approve":false}`).Code)
	assert.Equal(t, 404, approve(s, a.UserCode, `{"approve":false}`).Code)
	assert.Contains(t, poll(s, a.DeviceCode).Body.String(), "access_denied")
	assert.Contains(t, poll(s, a.DeviceCode).Body.String(), "invalid_grant")
	a = start(t, s)
	*now = now.Add(600 * time.Second)
	assert.Equal(t, 404, approve(s, a.UserCode, `{"approve":false}`).Code)
	_, ok := NormalizeUserCode("BCDFGHJſ")
	assert.False(t, ok)
}
func TestConcurrentSingleUse(t *testing.T) {
	s, _ := setup(t)
	a := start(t, s)
	require.Equal(t, 200, approve(s, a.UserCode, `{"approve":true,"scope":["calendar:0"],"lifetime":"30d"}`).Code)
	results := make(chan int, 10)
	for range 10 {
		go func() { results <- poll(s, a.DeviceCode).Code }()
	}
	success := 0
	for range 10 {
		status := <-results
		if status == 200 {
			success++
		} else {
			assert.Equal(t, 400, status)
		}
	}
	assert.Equal(t, 1, success)
}

func TestApprovedResourceRemoved(t *testing.T) {
	s, _ := setup(t)
	a := start(t, s)
	require.Equal(t, 200, approve(s, a.UserCode, `{"approve":true,"scope":["calendar:0"],"lifetime":"30d"}`).Code)
	s.ValidateScope = func(context.Context, *sql.Tx, []string) error { return ErrInvalidGrant }
	w := poll(s, a.DeviceCode)
	assert.Equal(t, 400, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_grant")
	var count int
	require.NoError(t, s.DB.QueryRow(`SELECT count(*) FROM minted`).Scan(&count))
	assert.Zero(t, count)
	require.NoError(t, s.DB.QueryRow(`SELECT count(*) FROM device_authorizations`).Scan(&count))
	assert.Zero(t, count)
}

func TestPerRequesterCap(t *testing.T) {
	s, _ := setup(t)
	for range 3 {
		start(t, s)
	}
	w := postForm(s.Authorize, url.Values{"client_id": {"test"}, "name": {"Test"}})
	assert.Equal(t, 429, w.Code)
	r := httptest.NewRequest("POST", "/", strings.NewReader("client_id=test&name=Other"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "127.0.0.2:1234"
	w = httptest.NewRecorder()
	s.Authorize(w, r)
	assert.Equal(t, 200, w.Code, w.Body.String())
}

func TestUnscopedConsentIsOptInAndPolicyValidated(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(fmt.Sprintf("allow=%t", allow), func(t *testing.T) {
			s, _ := setup(t)
			s.AllowEmptyScope = allow
			validated := 0
			s.ValidateScope = func(ctx context.Context, tx *sql.Tx, scope []string) error {
				validated++
				if len(scope) != 0 {
					return errors.New("resource scopes unsupported")
				}
				return nil
			}
			w := postForm(s.Authorize, url.Values{"client_id": {"test"}, "name": {"Unscoped"}})
			require.Equal(t, 200, w.Code, w.Body.String())
			var a Authorization
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &a))
			// Unsupported resource scope remains rejected regardless of the opt-in.
			assert.Equal(t, 400, approve(s, a.UserCode, `{"approve":true,"scope":["note:1"],"lifetime":"30d"}`).Code)
			w = approve(s, a.UserCode, `{"approve":true,"scope":[],"lifetime":"30d"}`)
			if !allow {
				assert.Equal(t, 400, w.Code)
				assert.Contains(t, poll(s, a.DeviceCode).Body.String(), "authorization_pending")
				return
			}
			require.Equal(t, 200, w.Code, w.Body.String())
			w = poll(s, a.DeviceCode)
			require.Equal(t, 200, w.Code, w.Body.String())
			var token Token
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &token))
			assert.Empty(t, token.Scope)
			assert.NotEmpty(t, token.AccessToken)
			assert.Contains(t, poll(s, a.DeviceCode).Body.String(), "invalid_grant")
			assert.Equal(t, 3, validated)
		})
	}
	// Opting in never bypasses the application's empty-scope policy.
	s, _ := setup(t)
	s.AllowEmptyScope = true
	a := start(t, s)
	assert.Equal(t, 400, approve(s, a.UserCode, `{"approve":true,"scope":[],"lifetime":"30d"}`).Code)
}

func TestUnscopedPolicyIsRecheckedAtExchange(t *testing.T) {
	s, _ := setup(t)
	s.AllowEmptyScope = true
	s.ValidateScope = func(context.Context, *sql.Tx, []string) error { return nil }
	w := postForm(s.Authorize, url.Values{"client_id": {"test"}, "name": {"Unscoped"}})
	require.Equal(t, 200, w.Code)
	var a Authorization
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &a))
	require.Equal(t, 200, approve(s, a.UserCode, `{"approve":true,"lifetime":"30d"}`).Code)
	s.ValidateScope = func(context.Context, *sql.Tx, []string) error { return ErrInvalidGrant }
	w = poll(s, a.DeviceCode)
	assert.Equal(t, 400, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_grant")
	var count int
	require.NoError(t, s.DB.QueryRow(`SELECT count(*) FROM minted`).Scan(&count))
	assert.Zero(t, count)
	require.NoError(t, s.DB.QueryRow(`SELECT count(*) FROM device_authorizations`).Scan(&count))
	assert.Zero(t, count)
}
