# go-server-common

Common things used by servers in Go.

## HTTP Host validation

Use `hostguard.New(publicURL, bindAddress, port)` before starting an HTTP
listener. It returns an immutable policy or a configuration error. Wrap the
handler with `policy.Middleware` **outside routing, authentication, and CSRF**,
so even GET, HEAD, OPTIONS, and unauthenticated routes reject unknown Hosts:

```go
policy, err := hostguard.New("https://mail.example.com:8443", "127.0.0.1", 8080)
if err != nil {
    return err
}
handler := policy.Middleware(
    csrf.MiddlewareOrigins(policy.Origins()...)(authenticatedRoutes),
)
```

The policy validates the literal `http.Request.Host`, ignoring `Forwarded`,
`X-Forwarded-Host`, and all other proxy headers. Rejected requests receive HTTP
421. This prevents a DNS-rebound foreign hostname from reaching an otherwise
unauthenticated loopback listener. It does not replace authentication or CSRF.

Allowed authorities are the configured public URL's host and effective port,
plus `localhost`, `127.0.0.1`, `::1`, and a concrete bind host at the listener
port. DNS names are case insensitive, IP spellings are canonicalized, and an
omitted request port is accepted only for an allowed port 80 or 443. Custom
ports must be explicit. Names must be ASCII DNS names (use punycode for IDNs);
trailing dots, IPv6 zones, malformed authorities, and unbracketed request IPv6
are rejected. Bind addresses are bare names or IPs, without a port or brackets.
Public URLs must use HTTP or HTTPS without credentials; URL paths do not affect
Host or origin validation.

Empty, `0.0.0.0`, and `::` wildcard bind addresses require an explicit public
URL and are not themselves added to the allowlist. Existing deployments that
use alternate DNS aliases must configure the actual public URL. Reverse
proxies must preserve that public Host (including custom ports), or send an
allowed local authority. Forwarding headers cannot extend the allowlist.

`policy.Origins()` supplies canonical browser origins to
`csrf.MiddlewareOrigins`: HTTP origins for direct local access and the public
URL's HTTP or HTTPS origin for proxy access. For direct TLS, configure its public HTTPS URL and explicitly add HTTPS
origins for any local aliases to the CSRF list; generated local origins assume
an HTTP listener. Host validation checks the destination on all
methods; CSRF separately checks the source of unsafe requests, retaining its
existing native-client behavior. Additional cross-origin clients can be added
to CSRF's origin list independently; doing so does not permit their Host.

## License

Copyright 2026 Mikael Ståldal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
