# burp-authentication-mapper

A [Claude Code](https://claude.ai/code) skill that maps authentication flows from Burp Suite HTTP History. Invoke it during or after a proxied session to automatically document how a web application handles authentication — without manually reading through raw requests.

## What It Does

Downloads the full Burp HTTP History from the Burp Suite proxy, classifies each request into a flow step, and produces:

- **ASCII sequence diagram** — Browser ↔ Server interaction with credential masking; static assets (`.gif`, `.jpg`, `.png`, `.ico`, `.css`, `.woff`, `.woff2`, `.ttf`, `.svg`) are excluded; on PortSwigger Web Security Academy labs (`web-security-academy.net`), `GET /academyLabHeader` WebSocket upgrade requests are also excluded
- **Session identifier table** — lifecycle state (pre-auth / authenticated / post-logout), request counts, and context for each unique session cookie
- **CSRF / anti-forgery token table** — where tokens are issued and where they are submitted

Works with any web application: form-based login, JWT/OAuth2 token flows, MFA challenges, SSO callbacks, and more.

---

## Installation & Usage

### Claude Code

Copy the skill directory into your Claude Code skills folder:

```bash
cp -r burp-authentication-mapper ~/.claude/skills/
```

Ensure the Burp Suite MCP server is running and connected, then invoke in a Claude Code session:

```
/burp-authentication-mapper
```

Claude will prompt you to select a source and scope (live Burp history or local XML file), download and parse the history, and output a fully-formatted authentication flow report.

---

### Google Gemini CLI

The `SKILL.md` format used by this skill is compatible with Gemini CLI's native Agent Skills system. There are two ways to use it.

#### Option A — gemini-cli-skillz (recommended)

[gemini-cli-skillz](https://github.com/intellectronica/gemini-cli-skillz) is a Gemini CLI extension that loads Anthropic-style `SKILL.md` skills directly. It lets you share the same skills directory between Claude Code and Gemini CLI without duplicating files.

**1. Install the extension:**

```bash
gemini extensions install https://github.com/intellectronica/gemini-cli-skillz
```

**2. Symlink your Claude Code skills directory:**

```bash
ln -s ~/.claude/skills ~/.skillz
```

Or if you cloned this repo standalone, point it at the skill directory:

```bash
mkdir -p ~/.skillz
cp -r burp-authentication-mapper ~/.skillz/
```

**3. Restart Gemini CLI.** The skill is loaded automatically. Describe what you want in natural language and Gemini will activate it:

```
Map the authentication flow I just captured in Burp
```

#### Option B — Native Gemini CLI Skills

Gemini CLI also has a built-in Agent Skills system that reads `SKILL.md` files from `~/.gemini/skills/`. The frontmatter format is identical.

**1. Copy the skill into the Gemini skills directory:**

```bash
mkdir -p ~/.gemini/skills
cp -r burp-authentication-mapper ~/.gemini/skills/
```

**2. Invoke via natural language** in a Gemini CLI session:

```
Map the authentication flow I just captured in Burp
```

Gemini activates the skill automatically when your request matches the skill's description.

#### Option C — Custom Slash Command

For an explicit `/burp-auth-map` slash command in Gemini CLI, create a TOML command file:

```bash
mkdir -p ~/.gemini/commands
```

Create `~/.gemini/commands/burp-auth-map.toml`:

```toml
description = "Map authentication flows from Burp Suite HTTP History"
prompt = """
Follow the workflow defined in the burp-authentication-mapper skill.
Prompt the user to select a scope (Last 25, Last 50, Last 100, or All in
history), then download the full Burp HTTP History to a local file, classify
the requests, and produce an ASCII sequence diagram, session identifier table,
and CSRF token table.
"""
```

Then reload commands without restarting:

```
/commands reload
```

Invoke with:

```
/burp-auth-map
```

> **Note:** The custom slash command works best when paired with Option A or B so Gemini has access to the full skill instructions, reference files, and parser script.

---

### Source and Scope Options

| Option | Mode | Filter Applied |
|---|---|---|
| Live — Last 50 requests | Live Burp MCP | `--last 50` |
| Live — Last 100 requests | Live Burp MCP | `--last 100` |
| Live — All in history | Live Burp MCP | *(no flag — returns everything)* |
| Local file | XML export | *(no flag — parses entire file)* |

---

## Repository Structure

```
burp-authentication-mapper/
├── SKILL.md                          # Skill definition — controls all workflow behavior
├── scripts/
│   └── parse_burp_history.py         # Burp history parser script
└── references/
    ├── auth_patterns.md              # Regex patterns and classification rules
    ├── security_checklist.md         # Security evaluation criteria
    └── example_output.md             # DVWA format reference
```

---

## Artifacts

### `SKILL.md`

The core skill definition. Defines the workflow Claude follows when the skill is invoked:

- **Step 0** — Single `AskUserQuestion` to select source and scope: Live (last 50/100/all) or Local XML file
- **Step 1** — *(Live mode only)* Downloads the full Burp HTTP History by paginating through `get_proxy_http_history` (count: 200 per page); saves every page to a local temp file — never processes results inline
- **Step 2** — Runs `parse_burp_history.py --report` with all collected file paths (or the local XML path); the script merges, deduplicates, classifies items, and outputs a complete formatted report; cleans up temp files and reports space freed (live mode only)
- **Step 3** — Displays the script's stdout verbatim — no regeneration

### `scripts/parse_burp_history.py`

A deterministic Python 3 parser for Burp history files. Run directly — never loaded into Claude's context.

**Capabilities:**
- Reads Burp MCP tool result files (auto-saved JSON array or raw text) **and** Burp XML exports (`Save items…`)
- Accepts multiple files and merges them, deduplicating by request content hash
- Optionally limits to the last N items (`--last N`) to match the selected scope
- Classifies each item into an auth flow category (Login Page Load, Credential Submission, Post-Auth Page Load, Static Asset, Logout, etc.)
- Extracts session cookies sent and set, with full security flag details (HttpOnly, Secure, SameSite, Max-Age, Domain, Path)
- Extracts hidden form fields and CSRF tokens from response HTML
- Extracts credential parameters from POST bodies with password masking (`****`)
- `--report` mode outputs a fully-formatted markdown report (sequence diagram, session table, CSRF table, notable findings) directly to stdout — no Claude generation needed

**Usage:**
```bash
# Report mode (used by the skill)
python3 scripts/parse_burp_history.py --report [--last N] <file(s)>

# JSON summary mode
python3 scripts/parse_burp_history.py [--last N] <file(s)>
```

### `references/auth_patterns.md`

Reference document containing classification patterns and extraction rules. Contains:

- Regex patterns for identifying login endpoints, credential parameters, session tokens, and logout flows
- Item classification rules table (method + path + status → category)
- Data extraction checklist (what to pull from requests and responses)
- Authentication flow type reference: form-based, JWT/OAuth2, MFA, SSO/OIDC authorization code flow, Basic/Digest

### `references/security_checklist.md`

Security evaluation criteria organized by category. Used as a reference when assessing an authentication flow. Covers:

| Category | Example Checks |
|---|---|
| Transport Security | HTTPS, Secure cookie flag, HSTS |
| Session Management | Session rotation on login, HttpOnly, SameSite, expiry, logout invalidation |
| CSRF Protection | Anti-forgery token presence, server-side validation, token rotation |
| Credential Handling | HTTPS transport, no credentials in URL, password field masking |
| Error Handling | Generic vs. specific error messages, stack trace exposure |
| Multi-Factor Auth | MFA present, bypass resistance, one-time token validation |
| Brute Force Protection | Rate limiting, account lockout, CAPTCHA, timing consistency |
| Logout Security | Server-side invalidation, cookie clearing, redirect behavior |

### `references/example_output.md`

A real output sample from mapping a DVWA (Damn Vulnerable Web Application) login flow. Documents the expected output format for reference. The report is now generated entirely by `parse_burp_history.py --report` — Claude displays it verbatim without regeneration.

---

## Requirements

- [Burp Suite](https://portswigger.net/burp) with the MCP server extension running
- Python 3 (for large-result processing via `parse_burp_history.py`)
- **Claude Code:** [claude.ai/code](https://claude.ai/code) with skills support
- **Gemini CLI:** [Gemini CLI](https://github.com/google-gemini/gemini-cli) with either native skills support or the [gemini-cli-skillz](https://github.com/intellectronica/gemini-cli-skillz) extension

---

## Example Output

```
**Source:** /path/to/history  **Scope:** all · 8 items · 1 host(s)
**Authentication type:** Form-based authentication with CSRF protection

---

## 127.0.0.1

### Sequence Diagram

Browser                                             Server
  |                                                 |
  |  1. GET /logout.php                             |
  |------------------------------------------------>|
  |  302 Found -> /login.php                        |
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
  |  3. POST /login.php                             |
  |    Cookie: PHPSESSID=95ce75...                  |
  |    username=admin                               |
  |    password=****                                |
  |    user_token=f970eb7f...                       |
  |------------------------------------------------>|
  |  302 Found -> /index.php                        |
  |  Set-Cookie: PHPSESSID=ff91cf...               |
  |  (session rotated on login)                     |
  |<------------------------------------------------|

### Session Identifiers

| # | PHPSESSID | State | Set On | Requests |
|---|---|---|---|---|
| 1 | `95ce754a2f847d048fd4af2a2fa51211` | Pre-auth | `/logout.php` | 4 |
| 2 | `ff91cf8b6f2491789cbdae695eed55e9` | Authenticated | `/login.php` | 3 |

### CSRF / Anti-Forgery Tokens

| Token Name | Value | Found In | Submitted In |
|---|---|---|---|
| `user_token` | `f970eb7fb77d44d785014b94d6c980f1` | `GET /login.php` (hidden field) | `POST /login.php` (form body) |
```
