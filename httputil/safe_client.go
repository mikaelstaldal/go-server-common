package httputil

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Special-purpose ranges are conservatively denied, including translation and
// tunneling ranges whose embedded destination could be private.
// Sources: https://www.iana.org/assignments/iana-ipv4-special-registry/
// and https://www.iana.org/assignments/iana-ipv6-special-registry/
var globalIPv6Prefix = netip.MustParsePrefix("2000::/3")

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), // IETF assignments, including Teredo and benchmarking
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), // 6to4
	netip.MustParsePrefix("3fff::/20"), // documentation
}

// IsBlockedIP rejects invalid, non-global and special-purpose addresses.
// IPv4-mapped IPv6 addresses use the same policy as their IPv4 counterparts.
func IsBlockedIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return true
	}
	// Only the currently allocated IPv6 global unicast space is allowed.
	// This also excludes NAT64, discard-only and other special-purpose space.
	if addr.Is6() && !globalIPv6Prefix.Contains(addr) {
		return true
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
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
		dialErr := fmt.Errorf("could not resolve URL host")
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
