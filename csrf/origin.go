package csrf

import (
	"fmt"
	"net/url"
)

// ResolveServerOrigin returns the "scheme://host" origin to use for CSRF
// validation (see Middleware). When publicURL is non-empty it must be a full
// URL such as "https://example.com" and its scheme and host are used; otherwise
// the origin defaults to "http://addr:port".
func ResolveServerOrigin(publicURL, addr string, port int) (string, error) {
	if publicURL == "" {
		return fmt.Sprintf("http://%s:%d", addr, port), nil
	}
	u, err := url.Parse(publicURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid public URL %q: must be a full URL like https://example.com", publicURL)
	}
	return u.Scheme + "://" + u.Host, nil
}
