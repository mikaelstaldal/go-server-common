package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
