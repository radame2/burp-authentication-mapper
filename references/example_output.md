# Example Output — DVWA Authentication Mapping

This is a real output from mapping the DVWA (Damn Vulnerable Web Application) authentication flow.
Use this as a format reference to ensure consistent output structure.

---

**Target:** DVWA @ `127.0.0.1:4280`
**Time window:** 13:39 - 13:44 UTC (Feb 16, 2026)
**Authentication type:** Form-based authentication with CSRF protection

---

## ASCII Sequence Diagram

```
Browser                                        DVWA Server
  |                                                 |
  |  1. GET /logout.php                             |
  |------------------------------------------------>|
  |  302 Found -> login.php                         |
  |  Set-Cookie: PHPSESSID=95ce75...                |
  |<------------------------------------------------|
  |                                                 |
  |  2. GET /login.php                              |
  |    Cookie: PHPSESSID=95ce75...                  |
  |------------------------------------------------>|
  |  200 OK                                         |
  |  Hidden: user_token=f970eb7f...                 |
  |<------------------------------------------------|
  |                                                 |
  |  3-4. GET /dvwa/css, /images  (static assets)   |
  |------------------------------------------------>|
  |<------------------------------------------------|
  |                                                 |
  |  5. POST /login.php                             |
  |    username=admin                               |
  |    password=****                                |
  |    user_token=f970eb7f...                       |
  |    Cookie: PHPSESSID=95ce75...                  |
  |------------------------------------------------>|
  |  302 Found -> index.php                         |
  |  Set-Cookie: PHPSESSID=ff91cf...                |
  |  (session rotated on login)                     |
  |<------------------------------------------------|
  |                                                 |
  |  6. GET /index.php                              |
  |    Cookie: PHPSESSID=ff91cf...                  |
  |------------------------------------------------>|
  |  200 OK — Authenticated DVWA dashboard          |
  |<------------------------------------------------|
  |                                                 |
  |  7-8. GET /images, /js  (static assets)         |
  |------------------------------------------------>|
  |<------------------------------------------------|
  |                                                 |
```

## Session Identifiers

| # | PHPSESSID | State | Used In | Context |
|---|---|---|---|---|
| 1 | `95ce754a2f847d048fd4af2a2fa51211` | Pre-auth (post-logout) | 4 requests | Issued by `GET /logout.php` 302 response |
| 2 | `ff91cf8b6f2491789cbdae695eed55e9` | Authenticated | 3 requests | Rotated on successful `POST /login.php` |

**Session lifecycle:** Logout destroys old session -> #1 issued (unauthenticated) -> Login rotates to #2 (authenticated)

## CSRF / Anti-Forgery Tokens

| Token Name | Value | Found In | Submitted In |
|---|---|---|---|
| `user_token` | `f970eb7fb77d44d785014b94d6c980f1` | `GET /login.php` (hidden field) | `POST /login.php` (form body) |

