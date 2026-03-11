# Changelog

All notable changes to burp-authentication-mapper are documented here.

## [1.4.0] - 2026-03-09

### Added
- Token tracking: auth tokens issued in JSON responses and carried in request headers (`Authorization`, `X-Token`, `X-Auth-Token`, etc.) are captured in a token identifier table with issuance endpoint, request count, and header usage
- Orphaned token detection: tokens seen in requests but absent from any captured response are flagged as orphaned entries
- Security assessment: evaluates the captured flow against a structured checklist covering 8 categories (Transport Security, Session Management, CSRF Protection, Credential Handling, Error Handling, MFA, Brute Force Protection, Logout Security) with Pass / Fail / Cannot determine ratings and evidence citations
- Burp MCP pre-flight connectivity check in Step 0: validates server reachability before attempting to fetch history, with detailed troubleshooting guidance if the check fails
- Auth-only diagram filtering: sequence diagrams suppress unauthenticated and preflight requests, showing only steps that carry session cookies, auth tokens, or CSRF fields

## [1.3.0] - 2026-03-03

### Added
- XML file support: `parse_burp_history.py` now accepts Burp Suite XML export files in addition to raw proxy history text
- `--report` flag: script outputs a fully-formatted markdown report (sequence diagrams, session tables, CSRF table) to stdout
- Local file mode: users can analyse a saved Burp history file without a live MCP connection
- Performance improvements to history parsing and host grouping

## [1.2.0] - 2026-03-02

### Changed
- Replaced time-window scope selection with item-count scope (Last 50 / Last 100 / All in history)
- Switched to full history pagination: fetches the entire Burp proxy history in 200-item pages before processing, rather than processing results inline
- Scope selection and source selection consolidated into a single Step 0 prompt

## [1.1.0] - 2026-02-28

### Fixed
- HTTP/2 compatibility: requests using HTTP/2 framing are now parsed correctly

### Changed
- Diagram filtering: hosts with no auth identifiers are omitted entirely; static assets and PortSwigger lab header requests are excluded

## [1.0.0] - 2026-02-28

### Added
- Initial release
- ASCII sequence diagram of Browser ↔ Server authentication flow with credential masking
- Session identifier table with lifecycle state (pre-auth / authenticated / post-logout), request counts, and cookie security flags (`Secure`, `HttpOnly`, `SameSite`)
- CSRF / anti-forgery token table showing where tokens are issued and submitted
- Gemini CLI integration via TOML slash command and `platforms/gemini/GEMINI.md`
- Support for form-based login, JWT/OAuth2 token flows, MFA challenges, SSO callbacks
