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

## Device authorization (`devicegrant`)

`devicegrant` implements RFC 8628 with single-use SQLite grants; the
`devicegrant/client` subpackage depends only on the standard library. Include
`devicegrant.DDL` in an app's versioned migrations. Configure a `Server` with
`DB`, an explicit `ClientIDs` allowlist, `VerificationURI`, `ValidateScope` and
`Mint`. Scope validation uses the supplied transaction to check app resources.
Minting must use **only the supplied transaction**: token insertion and device
row deletion commit together, so a failed mint can be retried and a successful
code never yields a second token. Device rows contain SHA-256 hashes, never raw
device codes or bearer secrets. Default expiry is ten minutes, poll interval five
seconds, and at most ten live grants (including approved and denied grants), with at
most three per socket IP (configurable with `MaxPending`/`MaxPerRequester`).
Behind a reverse proxy, the socket IP is the proxy address. Denied grants are
consumed when the CLI polls; expired rows are deleted on each new authorization.
The schema-v1 DDL is immutable; future schema additions use separate migrations.
A granted scope is revalidated at exchange time. An app returning
`ErrInvalidGrant` for a removed resource consumes the grant without minting.

Device grants require at least one granted resource scope by default. Apps whose
API tokens are unscoped can set `devicegrant.Server.AllowEmptyScope = true` to
allow empty-scope consent. `ValidateScope` still runs on approval and exchange,
including for an empty slice; the opt-in never bypasses app policy. The token's
OAuth `scope` is empty in that case. Scoped apps need no configuration change.

Mount `Authorize` and `Poll` on POST `/api/v1/oauth/device_authorization` and
`/api/v1/oauth/token`. Exempt these two routes from Basic authentication, but
refuse requests carrying bearer credentials, and retain the app's Host policy,
request body limit and recovery middleware. CLI POSTs carry no Origin/Referer;
normal CSRF middleware permits these non-browser requests. Do not exempt
browser requests from CSRF checks. Mount `Approval` on GET/POST
`/api/v1/oauth/device/{user_code}` behind **full-access authentication only**,
never bearer authentication. Approval POSTs need the usual CSRF protection.
The approval UI must show the code, name, requested scope/lifetime, creation
age, and requester (socket IP and User-Agent; forwarded headers are not trusted)
before allowing the user to edit scope/lifetime and approve or deny. A complete
verification URL pre-fills the code; it must never approve automatically.

Token responses include an optional `slug` extension for revocation. There are
no refresh tokens, discovery metadata, or dynamic client registration. The
client's `Login` receives the app's own `*http.Client`, both endpoint URLs,
request parameters, and a callback to display the code/URL. It waits between
polls, adds five seconds on `slow_down`, and stops at expiry, cancellation, or a
terminal typed `*client.Error`. Preserve the caller's HTTPS, proxy and redirect
policies. Never log device codes or access tokens.

## Terminal output (`termsafe`)

Use `termsafe.String(text)` for diagnostics and `termsafe.Copy(dst, src)` for
streamed terminal text. Both visibly escape terminal controls and Unicode bidi
controls, preserve TAB, LF, CRLF and ordinary Unicode, and escape malformed UTF-8
bytes individually. Controls use JSON-compatible Unicode escapes so valid JSON
retains its values. Escaping is idempotent.

The package does not detect terminals. Callers decide when to escape human-readable
output; use `io.Copy` for downloads and redirected output that must retain its
original bytes. Streaming failures propagate, and buffered text is flushed even
when a read fails.

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
