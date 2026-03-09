# Authentication Pattern Reference

## Regex Patterns for Item Classification

These patterns are used to classify and extract data from downloaded history items.

### Login/Authentication Endpoints
```
(?i)(login|signin|sign-in|authenticate|auth|oauth|token|session|sso|saml|openid|callback|authorize|grant|consent)
```

### Credential Submission Indicators
```
(?i)(username|password|passwd|credential|email|user_id|login_id|passphrase|secret|api_key|access_token|refresh_token|bearer|jwt|otp|mfa|totp|2fa)
```

### Session Management
```
(?i)(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|session_id|sid=|Set-Cookie|Cookie:|token=|csrf|xsrf|anti-forgery|user_token|authenticity_token|__RequestVerificationToken)
```

### Logout/Session Termination
```
(?i)(logout|signout|sign-out|revoke|invalidate|terminate|destroy|expire)
```

## Item Classification Rules

Classify each HTTP history item into one of these categories based on the indicators:

| Category | Method | Path Contains | Status | Other Indicators |
|---|---|---|---|---|
| Initial Visit / Redirect | GET | `/`, `/index.php`, `/index.html` | 302 | Location header contains "login" |
| Login Page Load | GET | `login`, `signin` | 200 | Response contains credential form fields and hidden CSRF tokens |
| Static Asset | GET | `.css`, `.js`, `.png`, `.jpg`, `.ico`, `.svg`, `.woff` | 200 | Loaded from login/auth page (Referer header) |
| Credential Submission | POST | `login`, `signin`, `auth` | 302/200 | Body contains username/password/credential params |
| Authentication Response | — | — | 302 | Set-Cookie with new session ID, Location to authenticated area |
| Post-Auth Page Load | GET | dashboard, home, index (not login) | 200 | Carries authenticated session cookie |
| MFA Challenge | GET/POST | `mfa`, `2fa`, `otp`, `verify`, `challenge` | 200 | Intermediate step between primary auth and session |
| Token Exchange | POST | `token`, `oauth` | 200 | Body contains grant_type, authorization_code, refresh_token |
| OAuth/SSO Callback | GET | `callback`, `redirect_uri`, `authorize` | 302 | Contains code/state parameters |
| Session Refresh | POST | `token`, `refresh` | 200 | Body contains refresh_token grant_type |
| Logout | GET/POST | `logout`, `signout`, `sign-out` | 302 | Session cookie cleared or new unauthenticated session issued |

## Data Extraction Checklist

### From Requests
- HTTP method and path
- Credential parameters (field names only — mask values with `****` for passwords)
- CSRF/anti-forgery tokens (field names and values)
- Session cookies sent (Cookie header)
- Auth token headers — matched against `AUTH_REQUEST_HEADERS` registry: `Authorization` (Bearer/Basic/Token prefix stripped), `X-Token`, `X-Auth-Token`, `X-Access-Token`, `X-Session-Token`, `X-API-Key`, `Api-Key`, `Token`
- Content-Type (form-urlencoded vs multipart vs JSON)

### From Responses
- HTTP status code and reason
- `Set-Cookie` headers with full attributes (HttpOnly, Secure, SameSite, Path, Domain, Max-Age)
- `Location` redirect header
- Hidden form fields in HTML (especially CSRF tokens)
- Error messages indicating auth failure
- `WWW-Authenticate` headers (Basic/Digest auth)
- JSON response body token fields — matched against `RESPONSE_TOKEN_FIELDS` registry: `token`, `access_token`, `refresh_token`, `id_token`, `auth_token`, `jwt`, `bearer_token`, `session_token`, `api_key`, `apikey` (searched top-level and one level deep)

Both registries are defined at the top of `parse_burp_history.py` — add new field or header names there to extend coverage without modifying any other code.

### Session Tracking
- Map each unique session ID value to its lifecycle state (pre-auth, authenticated, post-logout)
- Track session rotation: does the session ID change after successful login? (good practice)
- Track session fixation: does the same session ID persist across login? (vulnerability)
- Count how many requests use each session ID

## Authentication Flow Types

### Form-Based Authentication
1. GET login page → receives CSRF token in hidden field
2. POST credentials + CSRF token → 302 redirect on success
3. New session cookie set in redirect response
4. GET authenticated page with new session

### Token-Based (JWT/OAuth2 / Custom Header)
1. POST credentials to token endpoint
2. Receive token in JSON response body — field name varies by app (`token`, `access_token`, `jwt`, etc. — see `RESPONSE_TOKEN_FIELDS` in `parse_burp_history.py`)
3. Subsequent requests carry the token in a request header — header name varies by app (`Authorization: Bearer <token>`, `X-Token`, `X-Auth-Token`, etc. — see `AUTH_REQUEST_HEADERS` in `parse_burp_history.py`)

### Multi-Factor Authentication (MFA)
1. POST primary credentials → 200/302 to MFA challenge
2. GET/POST MFA challenge page
3. POST MFA code → 302 redirect on success
4. Session established

### SSO/OAuth2 Authorization Code Flow
1. Redirect to identity provider (302 to IdP authorize endpoint)
2. User authenticates at IdP
3. Redirect back with authorization code (302 to callback URL)
4. POST token exchange (code → access_token)
5. Session established locally

### Basic/Digest Authentication
- `Authorization: Basic <base64>` header in every request
- `WWW-Authenticate` header in 401 responses

## Hidden Fields of Interest
- CSRF tokens: `user_token`, `csrf_token`, `_token`, `authenticity_token`, `__RequestVerificationToken`
- Anti-automation tokens
- Hidden redirect URLs: `redirect_uri`, `next`, `return_to`, `continue`
- OAuth state parameters: `state`, `nonce`

## Cookie Security Attributes
| Attribute | Purpose | Good Value |
|---|---|---|
| `HttpOnly` | Prevents JavaScript access | Present |
| `Secure` | Only sent over HTTPS | Present (if HTTPS) |
| `SameSite` | Cross-origin control | `Strict` or `Lax` |
| `Path` | Scope restriction | `/` or narrow path |
| `Domain` | Domain scope | Specific domain |
| `Max-Age`/`Expires` | Session duration | Reasonable timeout |
