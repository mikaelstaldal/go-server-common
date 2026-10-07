// Package hostguard protects HTTP listeners against requests addressed to
// unconfigured hosts, including DNS rebinding against loopback listeners.
package hostguard

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

type authority struct {
	host string
	port int
}

// Policy holds an immutable allowlist. Construct it with New before starting
// the server. The local listener is assumed to serve HTTP; publicURL describes
// the browser-facing HTTP or HTTPS URL, possibly behind a reverse proxy.
type Policy struct {
	allowed map[authority]struct{}
	origins []string
}

// New derives allowed authorities and browser origins from publicURL, the
// bare bind address (without brackets or port), and the local listener port.
// Empty and unspecified bind addresses require an explicit publicURL.
// localhost, 127.0.0.1, ::1, and a concrete bind address are allowed at port.
// No DNS lookup or proxy header is used. Public URL paths are ignored.
// Direct HTTPS access through local aliases is not supported by the generated
// origins; supply additional HTTPS origins to CSRF if needed. For a listener
// opened on port zero, pass its actual assigned port after net.Listen.
func New(publicURL, addr string, port int) (*Policy, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid listener port %d", port)
	}
	p := &Policy{allowed: make(map[authority]struct{})}
	add := func(a authority, scheme string) {
		p.allowed[a] = struct{}{}
		origin := scheme + "://" + formatAuthority(a, scheme)
		if !slices.Contains(p.origins, origin) {
			p.origins = append(p.origins, origin)
		}
	}
	if publicURL != "" {
		u, err := url.Parse(publicURL)
		if err != nil || u.User != nil || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("invalid public URL %q: expected an HTTP or HTTPS URL without credentials", publicURL)
		}
		a, err := parseAuthority(u.Host)
		if err != nil {
			return nil, fmt.Errorf("invalid public URL authority: %w", err)
		}
		if a.port == 0 {
			a.port = defaultPort(u.Scheme)
		}
		add(a, u.Scheme)
	}
	wildcard := addr == ""
	if ip, err := netip.ParseAddr(addr); err == nil {
		if ip.Zone() != "" {
			return nil, fmt.Errorf("scoped bind addresses are not supported")
		}
		wildcard = ip.Unmap().IsUnspecified()
		addr = ip.String()
	} else if addr != "" {
		a, err := parseAuthority(addr)
		if err != nil || a.port != 0 || strings.ContainsAny(addr, "[]") {
			return nil, fmt.Errorf("invalid bind address %q: expected a bare host or IP", addr)
		}
		addr = a.host
	}
	if wildcard && publicURL == "" {
		return nil, fmt.Errorf("public URL is required for a wildcard bind address")
	}
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		add(authority{host, port}, "http")
	}
	if !wildcard {
		add(authority{addr, port}, "http")
	}
	return p, nil
}

// Origins returns an independent copy of the browser origins corresponding to
// this policy, for csrf.MiddlewareOrigins. Host validation and CSRF remain
// separate: Host applies to every request; CSRF checks the origin of writes.
func (p *Policy) Origins() []string { return slices.Clone(p.origins) }

// Middleware validates only r.Host on every method, before invoking next.
// Install it outside routing, authentication, and CSRF middleware. Proxies must
// preserve the public Host or send an allowed local authority. Foreign or
// malformed authorities receive HTTP 421 without reaching next.
func (p *Policy) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, err := parseAuthority(r.Host)
		if err == nil {
			if _, ok := p.allowed[a]; ok {
				next.ServeHTTP(w, r)
				return
			}
			// A Host without a port is valid for a configured default HTTP or HTTPS
			// authority. Never infer a port from TLS or untrusted forwarding headers.
			if a.port == 0 {
				for _, port := range []int{80, 443} {
					a.port = port
					if _, ok := p.allowed[a]; ok {
						next.ServeHTTP(w, r)
						return
					}
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMisdirectedRequest)
		_, _ = w.Write([]byte("{\"error\":\"invalid host\"}\n"))
	})
}

func defaultPort(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

func formatAuthority(a authority, scheme string) string {
	// Browsers serialize IPv4-mapped IPv6 with hexadecimal final components.
	if ip, err := netip.ParseAddr(a.host); err == nil && ip.Is4In6() {
		bytes := ip.As16()
		a.host = fmt.Sprintf("::ffff:%x:%x", uint16(bytes[12])<<8|uint16(bytes[13]), uint16(bytes[14])<<8|uint16(bytes[15]))
	}
	if a.port != defaultPort(scheme) {
		return net.JoinHostPort(a.host, strconv.Itoa(a.port))
	}
	if strings.Contains(a.host, ":") {
		return "[" + a.host + "]"
	}
	return a.host
}

// parseAuthority accepts ASCII DNS names, IPv4, and bracketed IPv6 only.
// Reject ambiguous URL syntax, IPv6 zones, empty ports, and unbracketed IPv6.
func parseAuthority(value string) (authority, error) {
	invalid := func() (authority, error) { return authority{}, fmt.Errorf("invalid authority %q", value) }
	if value == "" {
		return invalid()
	}
	for _, c := range value {
		if c <= 32 || c >= 127 || strings.ContainsRune("/?#@\\,%", c) {
			return invalid()
		}
	}
	host, portString := value, ""
	if strings.HasPrefix(value, "[") {
		end := strings.IndexByte(value, ']')
		if end < 0 {
			return invalid()
		}
		host = value[1:end]
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return invalid()
		}
		host = ip.String()
		suffix := value[end+1:]
		if suffix != "" {
			if !strings.HasPrefix(suffix, ":") || len(suffix) == 1 {
				return invalid()
			}
			portString = suffix[1:]
		}
	} else {
		if strings.Count(value, ":") > 1 {
			return invalid()
		}
		if i := strings.IndexByte(value, ':'); i >= 0 {
			host, portString = value[:i], value[i+1:]
			if portString == "" {
				return invalid()
			}
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			host = ip.String()
		} else {
			if len(host) > 253 {
				return invalid()
			}
			for _, label := range strings.Split(host, ".") {
				if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
					return invalid()
				}
				for _, c := range label {
					if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
						return invalid()
					}
				}
			}
			host = strings.ToLower(host)
		}
	}
	port := 0
	if portString != "" {
		for _, c := range portString {
			if c < '0' || c > '9' {
				return invalid()
			}
		}
		var err error
		port, err = strconv.Atoi(portString)
		if err != nil || port < 1 || port > 65535 {
			return invalid()
		}
	}
	return authority{host, port}, nil
}
