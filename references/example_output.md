# Example Output — DVWA Authentication Mapping

This is a representative output from mapping the DVWA (Damn Vulnerable Web Application) authentication flow.
Use this as a format reference to ensure consistent output structure.

Notes on filtering:
- Static assets (CSS, JS, images) are excluded from the diagram entirely
- Hosts with no auth identifiers are omitted from the report entirely
- On hosts that do have auth traffic, only steps carrying session cookies, tokens, or CSRF fields are shown

---

**Target:** DVWA @ `127.0.0.1:4280` · **Date:** 2026-02-16
**Source:** Live Burp Proxy History
**Scope:** last 25 · 8 items · 1 host(s)
**Authentication type:** Form-based authentication with CSRF protection

---

## 127.0.0.1

### Sequence Diagram

```
Browser                                             Server
  |                                                 |
  |  1. GET /logout.php                             |
  |------------------------------------------------>|
  |  302 Found -> /login.php                        |
  |  Set-Cookie: PHPSESSID=95ce75...51211           |
  |<------------------------------------------------|
  |                                                 |
  |  2. GET /login.php                              |
  |    Cookie: PHPSESSID=95ce75...51211             |
  |------------------------------------------------>|
  |  200 OK                                         |
  |  Hidden: user_token=f970eb7f...                 |
  |<------------------------------------------------|
  |                                                 |
  |  3. POST /login.php                             |
  |    Cookie: PHPSESSID=95ce75...51211             |
  |    username=admin                               |
  |    password=****                                |
  |    user_token=f970eb7f...                       |
  |------------------------------------------------>|
  |  302 Found -> /index.php                        |
  |  Set-Cookie: PHPSESSID=ff91cf...ee9             |
  |  (session rotated on login)                     |
  |<------------------------------------------------|
  |                                                 |
  |  4. GET /index.php                              |
  |    Cookie: PHPSESSID=ff91cf...ee9               |
  |------------------------------------------------>|
  |  200 OK                                         |
  |<------------------------------------------------|
  |                                                 |
```

### Session Identifiers

| # | session | State | Set On | Requests |
|---|---|---|---|---|
| 1 | `95ce754a2f847d048fd4af2a2fa51211` | Pre-auth | `/logout.php` | 4 |
| 2 | `ff91cf8b6f2491789cbdae695eed55e9` | Authenticated | `/login.php` | 3 |

**Cookie flags:** `Secure` ✓ · `HttpOnly` ✓ · `SameSite=Lax` ~

### Token Identifiers

No response body tokens detected.

### CSRF / Anti-Forgery Tokens

| Token Name | Value | Found In | Submitted In |
|---|---|---|---|
| `user_token` | `f970eb7fb77d44d785` | `/login.php` (hidden) | — |

---

## Notable Findings

| Risk | Finding | Detail |
|---|---|---|
| ✓ Good | Session rotation on login | New session issued on `POST /login.php` |
| ✓ Good | `Secure` + `HttpOnly` flags | All session cookies — prevents sniffing and JS theft |

---

## Security Assessment

### Transport Security

| Check | Result | Notes |
|---|---|---|
| Protocol | ✅ Pass | All requests use HTTP/1.1 on localhost; no external cleartext exposure |
| Secure flag on session cookies | ✅ Pass | `Secure` present on both PHPSESSID cookies |
| HSTS header | ⚠️ Cannot determine | No `Strict-Transport-Security` header observed; localhost lab environment |

### Session Management

| Check | Result | Notes |
|---|---|---|
| Session rotation on login | ✅ Pass | PHPSESSID changed from `95ce75...` to `ff91cf...` on `POST /login.php` |
| HttpOnly flag | ✅ Pass | `HttpOnly` present on both PHPSESSID cookies |
| SameSite attribute | ⚠️ Cannot determine | `SameSite=Lax` observed — acceptable but `Strict` preferred |
| Session scope | ⚠️ Cannot determine | Path/Domain scope not inspected in captured traffic |
| Session expiry | ⚠️ Cannot determine | No `Max-Age` or `Expires` observed on session cookies |
| Logout invalidation | ⚠️ Cannot determine | Logout redirects to login page but server-side invalidation not verifiable from proxy |

### CSRF Protection

| Check | Result | Notes |
|---|---|---|
| Anti-forgery token present | ✅ Pass | `user_token` hidden field issued in `GET /login.php` response |
| Token validated server-side | ⚠️ Cannot determine | Token submitted in `POST /login.php` but server validation not observable |
| Token rotation | ⚠️ Cannot determine | Only one login cycle captured; cannot compare across page loads |
| Token scope | ⚠️ Cannot determine | Single token observed; scope not determinable |

### Credential Handling

| Check | Result | Notes |
|---|---|---|
| Transport encryption | ⚠️ Cannot determine | Localhost lab (HTTP); acceptable for local testing only |
| Password field autocomplete | ⚠️ Cannot determine | Login form HTML not captured in proxy history |
| Credential exposure in URL | ✅ Pass | Credentials submitted in `POST /login.php` body, not in URL |
| Password masking | ⚠️ Cannot determine | Login form HTML not captured in proxy history |

### Error Handling

| Check | Result | Notes |
|---|---|---|
| Error messages | ⚠️ Cannot determine | No failed login attempt captured |
| Account lockout indicators | ⚠️ Cannot determine | No failed attempts captured |
| Stack traces | ⚠️ Cannot determine | No error responses captured |

### Multi-Factor Authentication

| Check | Result | Notes |
|---|---|---|
| MFA present | ❌ Fail | No MFA challenge observed; `POST /login.php` → `302` proceeds directly to session |
| MFA bypass | ⚠️ Cannot determine | No MFA flow present |
| MFA token validation | ⚠️ Cannot determine | No MFA flow present |

### Brute Force Protection

| Check | Result | Notes |
|---|---|---|
| Rate limiting | ⚠️ Cannot determine | Only one successful login captured |
| Account lockout | ⚠️ Cannot determine | No failed attempts captured |
| CAPTCHA | ⚠️ Cannot determine | Login form HTML not captured |
| Consistent timing | ⚠️ Cannot determine | Only one login response; no comparison possible |

### Logout Security

| Check | Result | Notes |
|---|---|---|
| Session invalidation | ⚠️ Cannot determine | `GET /logout.php` → 302 to `/login.php`; server-side invalidation not verifiable |
| New session on logout | ✅ Pass | New PHPSESSID `95ce75...` issued on `GET /logout.php` |
| Cookie clearing | ⚠️ Cannot determine | New session cookie set but old cookie expiry not observed |
| Redirect | ✅ Pass | `GET /logout.php` redirects to `/login.php` |

---

### Summary

| Result | Count |
|---|---|
| ✅ Pass | 7 |
| ❌ Fail | 1 |
| ⚠️ Cannot determine | 16 |

**Top priority issues:**

1. **[Medium] No MFA observed** — single-factor authentication only; no second factor challenge in the captured flow
2. **[Informational] Session expiry not observed** — no `Max-Age` or `Expires` on session cookies; session lifetime unknown

> Many "Cannot determine" results reflect missing coverage (no failed login, no form HTML captured). Re-run after capturing a complete session including login failures and a full page load for a more complete assessment.
