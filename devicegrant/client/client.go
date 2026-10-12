// Package client is a standard-library-only RFC 8628 client. The caller supplies
// an HTTP client whose transport and redirect policies fit its application.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

type Error struct {
	Code   string `json:"error"`
	Status int    `json:"-"`
}

func (e *Error) Error() string { return "device login: " + e.Code }

type Authorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}
type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
	Slug        string `json:"slug"`
}

func post(ctx context.Context, client *http.Client, endpoint string, values url.Values, result any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil {
		return err
	}
	if len(body) > 65536 {
		return errors.New("device login: oversized response")
	}
	if resp.StatusCode != http.StatusOK {
		var e Error
		if json.Unmarshal(body, &e) == nil && e.Code != "" {
			e.Status = resp.StatusCode
			return &e
		}
		return &Error{Code: fmt.Sprintf("HTTP %d", resp.StatusCode), Status: resp.StatusCode}
	}
	return json.Unmarshal(body, result)
}

// Login starts a flow and calls display once before polling. No credentials are
// read or sent. Polls wait for the supplied interval, also after slow_down.
func Login(ctx context.Context, client *http.Client, authorizationURL, tokenURL, clientID, name, scope, lifetime string, display func(Authorization) error) (Token, error) {
	var auth Authorization
	var token Token
	started := time.Now()
	err := post(ctx, client, authorizationURL, url.Values{"client_id": {clientID}, "name": {name}, "scope": {scope}, "lifetime": {lifetime}}, &auth)
	if err != nil {
		return token, err
	}
	// Bound untrusted duration arithmetic. Grants normally expire after ten minutes.
	if auth.DeviceCode == "" || auth.UserCode == "" || auth.VerificationURI == "" || auth.ExpiresIn <= 0 || auth.ExpiresIn > 86400 || auth.Interval < 0 || auth.Interval > 86400 {
		return token, errors.New("device login: invalid authorization response")
	}
	until := started.Add(time.Duration(auth.ExpiresIn) * time.Second)
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	if err = display(auth); err != nil {
		return token, err
	}
	interval := time.Duration(auth.Interval) * time.Second
	if interval == 0 {
		interval = 5 * time.Second
	}
	interrupted := false
	for {
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return token, ctx.Err()
		case <-timer.C:
		}
		err = post(ctx, client, tokenURL, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {auth.DeviceCode}, "client_id": {clientID}}, &token)
		if err == nil {
			if token.AccessToken == "" || !strings.EqualFold(token.TokenType, "Bearer") || token.ExpiresIn <= 0 {
				return Token{}, errors.New("device login: invalid token response")
			}
			return token, nil
		}
		var protocol *Error
		if !errors.As(err, &protocol) {
			// A dropped connection must not abandon a pending approval.
			// Retry only polling; authorization requests may create a new grant.
			if retryablePollingError(err) {
				interrupted = true
				interval = min(interval*2, 1*time.Hour)
				continue
			}
			return token, err
		}
		if protocol.Status >= 500 || protocol.Status == 429 {
			interval = min(interval*2, 1*time.Hour)
			continue
		}
		switch protocol.Code {
		case "authorization_pending":
		case "slow_down":
			interval += 5 * time.Second
		default:
			if protocol.Code == "invalid_grant" && interrupted {
				return token, fmt.Errorf("device login: the interrupted response may have contained an issued token; check the server's API token list and revoke any unused token before starting again: %w", err)
			}
			return token, err
		}
	}
}

// Inspect each wrapper: url.Error.Timeout only checks its immediate cause.
func retryablePollingError(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	for err != nil {
		if network, ok := err.(net.Error); ok && network.Timeout() {
			return true
		}
		err = errors.Unwrap(err)
	}
	return false
}
