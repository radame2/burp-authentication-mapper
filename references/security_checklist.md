# Authentication Security Checklist

Evaluate each area and present findings as a table with Finding, Detail, and Risk columns.
Risk ratings: HIGH, MEDIUM, LOW, GOOD (for positive findings), Informational.

## Transport Security

| Check | Good | Bad |
|---|---|---|
| Protocol | HTTPS with valid certificate | Plain HTTP — credentials in cleartext |
| Secure flag on session cookies | Present | Missing — cookie sent over HTTP |
| HSTS header | `Strict-Transport-Security` present | Missing — vulnerable to downgrade |

## Session Management

| Check | Good | Bad |
|---|---|---|
| Session rotation on login | Session ID changes after authentication | Same session ID pre/post auth (session fixation) |
| HttpOnly flag | Present on session cookies | Missing — XSS can steal session |
| SameSite attribute | `Strict` or `Lax` | `None` or missing — CSRF risk |
| Session scope | Narrow Path/Domain | Overly broad scope |
| Session expiry | Reasonable Max-Age/Expires | No expiry or excessively long (>24h) |
| Logout invalidation | Session destroyed server-side | Cookie cleared but session still valid |

## CSRF Protection

| Check | Good | Bad |
|---|---|---|
| Anti-forgery token present | Hidden field with unique token per form | No CSRF token on state-changing forms |
| Token validated server-side | Stale/reused token rejected | Token not checked or accepted |
| Token rotation | New token issued per page load | Same token across multiple requests |
| Token scope | Per-form or per-session | Global/predictable token |

## Credential Handling

| Check | Good | Bad |
|---|---|---|
| Transport encryption | Credentials sent over HTTPS | Plaintext credentials over HTTP |
| Password field autocomplete | `autocomplete="off"` or `autocomplete="new-password"` | Default autocomplete enabled |
| Credential exposure in URL | Credentials in POST body only | Credentials in GET query string |
| Password masking | Input type="password" | Password in plaintext input field |

## Error Handling

| Check | Good | Bad |
|---|---|---|
| Error messages | Generic: "Invalid credentials" | Specific: "User not found" or "Wrong password" (username enumeration) |
| Account lockout indicators | No lockout info exposed | "Account locked after N attempts" (lockout policy disclosure) |
| Stack traces | No technical details | Server errors or stack traces in response |

## Multi-Factor Authentication

| Check | Good | Bad |
|---|---|---|
| MFA present | Second factor required | Single-factor only |
| MFA bypass | No bypass possible | MFA skippable by modifying request flow |
| MFA token validation | One-time use, time-limited | Reusable or long-lived MFA tokens |

## Brute Force Protection

| Check | Good | Bad |
|---|---|---|
| Rate limiting | Requests throttled after N attempts | No rate limiting observed |
| Account lockout | Temporary lockout after failures | No lockout mechanism |
| CAPTCHA | CAPTCHA after failed attempts | No anti-automation |
| Consistent timing | Same response time for valid/invalid users | Timing differences reveal valid usernames |

## Logout Security

| Check | Good | Bad |
|---|---|---|
| Session invalidation | Server-side session destroyed | Only client-side cookie cleared |
| New session on logout | Fresh unauthenticated session issued | Old session reusable after logout |
| Cookie clearing | Session cookie explicitly expired/deleted | Cookie persists after logout |
| Redirect | Redirects to login page | Redirects to authenticated content |
