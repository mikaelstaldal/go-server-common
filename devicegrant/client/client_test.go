package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogin(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Empty(t, r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/auth":
			assert.Equal(t, "cli", r.Form.Get("client_id"))
			_ = json.NewEncoder(w).Encode(Authorization{"device", "BCDF-GHJK", "https://example.org/approve", "", 20, 1})
		case "/token":
			calls++
			assert.Equal(t, "urn:ietf:params:oauth:grant-type:device_code", r.Form.Get("grant_type"))
			if calls == 1 {
				w.WriteHeader(400)
				_ = json.NewEncoder(w).Encode(Error{Code: "authorization_pending"})
			} else {
				_ = json.NewEncoder(w).Encode(Token{"secret", "Bearer", 100, "calendar:0", "name"})
			}
		default:
			t.Error("unexpected path")
		}
	}))
	defer server.Close()
	displayed := false
	token, err := Login(context.Background(), server.Client(), server.URL+"/auth", server.URL+"/token", "cli", "Name", "calendar:0", "30d", func(a Authorization) error { displayed = true; assert.Equal(t, "BCDF-GHJK", a.UserCode); return nil })
	require.NoError(t, err)
	assert.True(t, displayed)
	assert.Equal(t, "secret", token.AccessToken)
	assert.Equal(t, 2, calls)
}
func TestCancellationAndTypedErrors(t *testing.T) {
	for _, code := range []string{"access_denied", "expired_token", "invalid_grant", "invalid_client", "unsupported_grant_type", "invalid_request"} {
		t.Run(code, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(400)
				_ = json.NewEncoder(w).Encode(Error{Code: code})
			}))
			defer server.Close()
			_, err := Login(context.Background(), server.Client(), server.URL, server.URL, "cli", "Name", "", "30d", func(Authorization) error { return nil })
			var e *Error
			require.ErrorAs(t, err, &e)
			assert.Equal(t, code, e.Code)
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Authorization{"device", "CODE", "https://example.org", "", 600, 5})
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := Login(ctx, server.Client(), server.URL, server.URL, "cli", "Name", "", "30d", func(Authorization) error { return nil })
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestPollingBackoff(t *testing.T) {
	var times []time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth" {
			_ = json.NewEncoder(w).Encode(Authorization{"device", "CODE", "https://example.org", "", 30, 1})
			return
		}
		times = append(times, time.Now())
		switch len(times) {
		case 1:
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(Error{Code: "slow_down"})
		case 2:
			w.WriteHeader(500)
			_ = json.NewEncoder(w).Encode(Error{Code: "server_error"})
		default:
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(Error{Code: "access_denied"})
		}
	}))
	defer server.Close()
	_, err := Login(context.Background(), server.Client(), server.URL+"/auth", server.URL+"/token", "cli", "Name", "", "30d", func(Authorization) error { return nil })
	var protocol *Error
	require.ErrorAs(t, err, &protocol)
	assert.Equal(t, "access_denied", protocol.Code)
	require.Len(t, times, 3)
	assert.GreaterOrEqual(t, times[1].Sub(times[0]), 6*time.Second)
	assert.GreaterOrEqual(t, times[2].Sub(times[1]), 12*time.Second)
}

// transportFunc lets tests inject failures before a polling response is received.
type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPollingRetriesDroppedConnections(t *testing.T) {
	for _, failure := range []error{os.ErrDeadlineExceeded, io.EOF, io.ErrUnexpectedEOF, syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE} {
		t.Run(failure.Error(), func(t *testing.T) {
			t.Parallel()
			var polls []time.Time
			authorizations := 0
			httpClient := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				body := `{"device_code":"device","user_code":"CODE","verification_uri":"https://example.org","expires_in":20,"interval":1}`
				if r.URL.Path == "/auth" {
					authorizations++
				} else {
					polls = append(polls, time.Now())
					if len(polls) == 1 {
						return nil, fmt.Errorf("connection interrupted: %w", failure)
					}
					body = `{"access_token":"secret","token_type":"Bearer","expires_in":60}`
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			token, err := Login(context.Background(), httpClient, "https://example.org/auth", "https://example.org/token", "cli", "Name", "", "1m", func(Authorization) error { return nil })
			require.NoError(t, err)
			assert.Equal(t, "secret", token.AccessToken)
			assert.Equal(t, 1, authorizations)
			require.Len(t, polls, 2)
			assert.GreaterOrEqual(t, polls[1].Sub(polls[0]), 2*time.Second)
		})
	}
}

func TestDroppedAuthorizationIsNotRetried(t *testing.T) {
	calls := 0
	httpClient := &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, io.EOF
	})}
	_, err := Login(context.Background(), httpClient, "https://example.org/auth", "https://example.org/token", "cli", "Name", "", "1m", func(Authorization) error { t.Fatal("unexpected display"); return nil })
	require.ErrorIs(t, err, io.EOF)
	assert.Equal(t, 1, calls)
}

func TestPollingPermanentTransportError(t *testing.T) {
	failure := errors.New("certificate is not trusted")
	calls := 0
	httpClient := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/auth" {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"device_code":"device","user_code":"CODE","verification_uri":"https://example.org","expires_in":20,"interval":1}`)), Header: make(http.Header)}, nil
		}
		calls++
		return nil, &url.Error{Op: "Post", URL: r.URL.String(), Err: failure}
	})}
	_, err := Login(context.Background(), httpClient, "https://example.org/auth", "https://example.org/token", "cli", "Name", "", "1m", func(Authorization) error { return nil })
	require.ErrorIs(t, err, failure)
	assert.Equal(t, 1, calls)
}

func TestLostTokenResponseExplainsRecovery(t *testing.T) {
	calls := 0
	httpClient := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"device_code":"device","user_code":"CODE","verification_uri":"https://example.org","expires_in":20,"interval":1}`
		status := http.StatusOK
		if r.URL.Path == "/token" {
			calls++
			if calls == 1 {
				return nil, io.EOF
			}
			status = http.StatusBadRequest
			body = `{"error":"invalid_grant"}`
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	_, err := Login(context.Background(), httpClient, "https://example.org/auth", "https://example.org/token", "cli", "Name", "", "1m", func(Authorization) error { return nil })
	var protocol *Error
	require.ErrorAs(t, err, &protocol)
	assert.Equal(t, "invalid_grant", protocol.Code)
	assert.ErrorContains(t, err, "revoke any unused token")
	assert.Equal(t, 2, calls)
}
