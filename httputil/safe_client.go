package httputil

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// IsBlockedIP reports whether an IP must not be connected to (loopback,
// private, link-local or unspecified addresses).
func IsBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// ValidateExternalURL checks that the URL is safe to fetch (not localhost or private IPs).
func ValidateExternalURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https")
	}
	hostname := u.Hostname()
	if hostname == "" {
		return fmt.Errorf("URL must have a hostname")
	}
	lower := strings.ToLower(hostname)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return fmt.Errorf("URL must not point to localhost")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		// Don't leak resolver/hostname details to the client (SSRF oracle).
		log.Printf("DNS lookup failed for %s: %v", hostname, err)
		return fmt.Errorf("could not resolve URL host")
	}

	for _, ip := range ips {
		if IsBlockedIP(ip.IP) {
			return fmt.Errorf("URL must not point to a private or local address")
		}
	}
	return nil
}

// SafeDialContext returns a DialContext function for http.Transport that
// resolves the destination host, validates every candidate IP, and dials one
// of the validated IPs directly. This closes the TOCTOU / DNS-rebinding window
// between validation and connection: the connection cannot be made to a
// different address than the one that was checked.
func SafeDialContext(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			log.Printf("DNS lookup failed for %s: %v", host, err)
			return nil, fmt.Errorf("could not resolve URL host")
		}
		for _, ip := range ips {
			if IsBlockedIP(ip.IP) {
				return nil, fmt.Errorf("URL must not point to a private or local address")
			}
		}
		var dialErr error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if err != nil {
				dialErr = err
				continue
			}
			return conn, nil
		}
		return nil, dialErr
	}
}

// SafeCheckRedirect returns an http.Client.CheckRedirect function that stops
// after maxRedirects hops and re-validates every redirect target, so a public
// URL cannot redirect to an internal address.
func SafeCheckRedirect(maxRedirects int) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		return ValidateExternalURL(req.URL.String())
	}
}

// NewSafeHTTPClient returns an HTTP client hardened against SSRF. It resolves
// and validates the destination IP at dial time (closing the TOCTOU /
// DNS-rebinding window between validation and fetch) and re-validates every
// redirect target so a public URL cannot redirect to an internal address.
func NewSafeHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		DialContext: SafeDialContext(dialer),
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: SafeCheckRedirect(10),
	}
}
