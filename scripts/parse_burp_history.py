#!/usr/bin/env python3
"""
Parse Burp Suite HTTP History files.

Extracts authentication-related items, deduplicates across multiple result
files, classifies each item, and outputs either structured JSON or a
pre-formatted markdown report.

Usage:
    python3 parse_burp_history.py [--last N] [--report] [--version] file1 [file2 ...]

    --last N      Keep only the last N items (most recent in fetch order).
                  Omit or use 0 to return all items.
    --report      Output a pre-formatted markdown report (sequence diagram,
                  session table, CSRF table, findings) instead of JSON.
    --version     Print version and changelog, then exit.

Output (default): JSON array of classified items to stdout; summary to stderr.
Output (--report): Formatted markdown report to stdout.

Input formats accepted:
    - Burp XML export  (<?xml ...> / <items> — local "Save items" export)
    - JSON array       ([{"type": "text", "text": "..."}] — auto-saved by system)
    - Raw text         (item content written inline)
"""

import argparse
import base64
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


VERSION = "2.0.0"

CHANGELOG = """
v2.0.0 (2026-03-12)
  - Replaced allowlist-based session cookie detection (extract_session_ids) with a
    generic parse-all approach: every Set-Cookie header is now parsed and classified
    by purpose using flag heuristics and value shape, not cookie name.
  - Cookie classification kinds:
      session  — HttpOnly=true, not long-lived (typical server-side session)
      jwt      — value matches eyJ...eyJ JWT structure
      device   — Max-Age > 30 days (persistent device/tracking cookie)
      csrf     — name matches csrf/xsrf/forgery, or non-HttpOnly + high-entropy
                 value (double-submit cookie pattern)
      other    — everything else
  - XSRF-TOKEN and other CSRF cookies delivered via Set-Cookie are now shown
    in the CSRF / Anti-Forgery Tokens section alongside hidden form fields.
  - Custom session cookie names (e.g. hack_the_box_session, laravel_session,
    global_device_cookie_*) are tracked automatically without registration.
  - Cookie request header is now parsed generically — all name=value pairs
    extracted, not just those matching a fixed list of known names.
  - Session Identifiers table renamed to "Session & Cookie Identifiers" and
    now lists every session/jwt/device cookie with per-cookie flag annotations
    (HttpOnly, Secure, SameSite, Max-Age).
  - Fixed: HttpOnly, Secure, SameSite, and Max-Age flag detection is now
    case-insensitive (previously missed lowercase directive values).
  - Added --version flag to print version and changelog.

v1.0.0
  - Initial release.
"""


# ---------------------------------------------------------------------------
# Configurable token registries  (extend these lists to support new tokens)
# ---------------------------------------------------------------------------

# JSON field names to search for in response bodies (top-level and one level
# deep inside nested objects).
RESPONSE_TOKEN_FIELDS = [
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "auth_token",
    "jwt",
    "bearer_token",
    "session_token",
    "api_key",
    "apikey",
]

# HTTP request header names that carry an auth token.
AUTH_REQUEST_HEADERS = [
    "Authorization",
    "X-Token",
    "X-Auth-Token",
    "X-Access-Token",
    "X-Session-Token",
    "X-API-Key",
    "Api-Key",
    "Token",
]


# ---------------------------------------------------------------------------
# File parsing
# ---------------------------------------------------------------------------

def _parse_xml_time(s):
    """Parse Burp XML export timestamp: 'Sun Mar 01 15:18:29 EST 2026'.

    Strips the timezone abbreviation and tries common strptime patterns.
    Returns a UTC datetime (timezone offset is ignored — used for ordering only).
    """
    if not s:
        return None
    cleaned = re.sub(r'\s+[A-Z]{2,5}(?=\s)', ' ', s.strip())
    for fmt in ("%a %b %d %H:%M:%S %Y", "%a %b  %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(cleaned, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _extract_items_from_xml(raw):
    """Extract request/response pairs from a Burp XML export ("Save items").

    Decodes base64 request/response bodies and normalises line endings to the
    escaped form (\\r\\n) expected by all downstream parsing functions.
    Stores the Burp export timestamp in the notes field for correct ordering.
    """
    root = ET.fromstring(raw)
    pairs = []
    for item in root.findall("item"):
        req_el = item.find("request")
        resp_el = item.find("response")
        if req_el is None or resp_el is None:
            continue

        req_text = req_el.text or ""
        resp_text = resp_el.text or ""
        time_str = item.findtext("time") or ""

        if req_el.get("base64") == "true" and req_text:
            req_text = base64.b64decode(req_text).decode("utf-8", errors="replace")
        if resp_el.get("base64") == "true" and resp_text:
            resp_text = base64.b64decode(resp_text).decode("utf-8", errors="replace")

        req_text = req_text.replace("\r\n", "\\r\\n").replace("\n", "\\r\\n")
        resp_text = resp_text.replace("\r\n", "\\r\\n").replace("\n", "\\r\\n")

        pairs.append((req_text, resp_text, time_str))
    return list(reversed(pairs))


def extract_items_from_file(filepath):
    """Extract request/response pairs from a Burp history file.

    Accepts three formats:
    - Burp XML export: <?xml ...> <items> (local "Save items" export)
    - JSON array: [{"type": "text", "text": "..."}]  (auto-saved by system)
    - Raw text: item content written directly (manually saved inline results)
    """
    with open(filepath) as f:
        raw = f.read()

    if raw.lstrip().startswith("<?xml") or raw.lstrip().startswith("<items"):
        return _extract_items_from_xml(raw)

    try:
        data = json.loads(raw)
        text = data[0]["text"] if isinstance(data, list) else data.get("text", str(data))
    except (json.JSONDecodeError, KeyError, IndexError):
        text = raw

    pairs = re.findall(
        r'\{"request":"(.*?)","response":"(.*?)","notes":"(.*?)"\}',
        text,
        re.DOTALL,
    )
    return pairs


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def parse_date_header(response_text):
    """Parse the Date header from a response into a UTC datetime, if present."""
    match = re.search(r"Date:\s*(.+?)\\r\\n", response_text)
    if not match:
        return None
    date_str = match.group(1).strip()
    try:
        return datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %Z").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


def classify_item(method, path, status, location, body):
    """Classify an HTTP history item into an authentication flow category."""
    path_lower = path.lower()
    location_lower = location.lower()

    if "logout" in path_lower or "signout" in path_lower or "sign-out" in path_lower:
        return "Logout"

    if (
        method == "GET"
        and path_lower in ("/", "/index.php", "/index.html", "/default.aspx")
        and status == "302"
        and "login" in location_lower
    ):
        return "Initial Visit / Redirect"

    if method == "GET" and "login" in path_lower and status == "200":
        return "Login Page Load"

    if method == "POST" and ("login" in path_lower or "auth" in path_lower or "token" in path_lower):
        has_creds = bool(
            re.search(r"(username|password|email|user|passwd|credential)", body, re.I)
        )
        if has_creds or "login" in path_lower:
            return "Credential Submission"
        if "token" in path_lower:
            return "Token Exchange"

    if method in ("GET", "POST") and re.search(r"(mfa|2fa|otp|verify|challenge)", path_lower):
        return "MFA Challenge"

    if re.search(r"(callback|redirect_uri|authorize)", path_lower):
        return "OAuth/SSO Callback"

    if re.search(r"\.(css|js|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot)$", path_lower):
        return "Static Asset"

    if method == "GET" and status == "200" and "login" not in path_lower:
        return "Post-Auth Page Load"

    if status in ("301", "302", "303", "307", "308"):
        return "Redirect"

    return "Other"


def extract_cookie_flags(set_cookie_value):
    """Extract security flags from a Set-Cookie header value.

    All directive names are matched case-insensitively to handle servers
    that emit lowercase variants (e.g. 'httponly', 'secure', 'samesite=lax').
    """
    flags = {}
    flags["HttpOnly"] = bool(re.search(r"(?i)\bhttponly\b", set_cookie_value))
    flags["Secure"] = bool(re.search(r"(?i)\bsecure\b", set_cookie_value))
    samesite = re.search(r"(?i)\bsamesite=(\w+)", set_cookie_value)
    flags["SameSite"] = samesite.group(1).capitalize() if samesite else None
    maxage = re.search(r"(?i)\bmax-age=(\d+)", set_cookie_value)
    flags["Max-Age"] = int(maxage.group(1)) if maxage else None
    domain = re.search(r"(?i)\bdomain=([^;\s]+)", set_cookie_value)
    flags["Domain"] = domain.group(1) if domain else None
    path_m = re.search(r"(?i)\bpath=([^;\s]+)", set_cookie_value)
    flags["Path"] = path_m.group(1) if path_m else None
    return flags


def classify_cookie(name, value, flags):
    """Classify a cookie into one of five purpose kinds.

    Evaluation order (first match wins):
      csrf    — name matches csrf/xsrf/forgery/antiforgery
      jwt     — value is a well-formed JWT (eyJ…. eyJ… pattern)
      device  — Max-Age > 30 days (persistent device/tracking cookie)
      session — HttpOnly=True (protected from JS, typical session cookie)
      csrf    — not HttpOnly + high-entropy value (double-submit cookie pattern)
      other   — everything else
    """
    name_lower = name.lower()

    if re.search(r"(csrf|xsrf|forgery|antiforgery)", name_lower):
        return "csrf"

    if re.match(r"^eyJ[A-Za-z0-9_\-]+\.eyJ", value):
        return "jwt"

    max_age = flags.get("Max-Age")
    if max_age and max_age > 86400 * 30:
        return "device"

    if flags.get("HttpOnly"):
        return "session"

    if not flags.get("HttpOnly") and len(value) > 20:
        return "csrf"

    return "other"


def parse_all_set_cookies(response_text):
    """Parse every Set-Cookie header in a response into structured dicts.

    Returns a list of dicts: {name, value, raw, flags, kind}.
    Malformed Set-Cookie entries (no name=value pair) are skipped.
    """
    raw_list = re.findall(r"Set-Cookie:\s*(.+?)\\r\\n", response_text)
    result = []
    for raw in raw_list:
        first = raw.split(";")[0].strip()
        if "=" not in first:
            continue
        name, value = first.split("=", 1)
        name = name.strip()
        value = value.strip()
        flags = extract_cookie_flags(raw)
        kind = classify_cookie(name, value, flags)
        result.append({"name": name, "value": value, "raw": raw, "flags": flags, "kind": kind})
    return result


def parse_cookie_header(request_text):
    """Parse all cookies from the Cookie request header.

    Returns a dict mapping cookie name -> value for every cookie present.
    """
    match = re.search(r"Cookie:\s*(.+?)\\r\\n", request_text)
    if not match:
        return {}
    cookies = {}
    for part in match.group(1).split(";"):
        part = part.strip()
        if "=" in part:
            name, value = part.split("=", 1)
            cookies[name.strip()] = value.strip()
    return cookies


def extract_hidden_fields(response_text):
    """Extract hidden form fields from HTML in a response."""
    return re.findall(
        r"type=['\"]hidden['\"].*?name=['\"](\w+)['\"].*?value=['\"]([^'\"]+)['\"]",
        response_text,
    )


def extract_cred_params(body):
    """Extract credential-related parameters from a POST body."""
    params = re.findall(
        r"(username|password|passwd|email|user|Login|user_token|csrf_token|"
        r"authenticity_token|access_token|refresh_token|grant_type|code|state)=([^&\\]+)",
        body,
        re.I,
    )
    return params


def extract_response_body_tokens(response_text):
    """Extract auth tokens from a JSON response body.

    Searches RESPONSE_TOKEN_FIELDS in the top-level JSON object and one level
    deep inside any nested objects.  Returns a dict mapping field_name -> value.
    Add new field names to RESPONSE_TOKEN_FIELDS to extend coverage.

    Handles both escaped (\\r\\n as 4 chars) and literal (CR+LF as 2 chars)
    line endings so the same function works for XML-export and MCP-JSON inputs.
    """
    tokens = {}
    body = ""
    for sep in ("\\r\\n\\r\\n", "\r\n\r\n", "\n\n"):
        if sep in response_text:
            body = response_text.split(sep, 1)[1]
            break
    if not body.strip():
        return tokens
    body = body.replace('\\"', '"').replace('\\\\', '\\')
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return tokens
    if not isinstance(data, dict):
        return tokens

    def _scan(obj):
        for field in RESPONSE_TOKEN_FIELDS:
            if field in obj and isinstance(obj[field], str) and obj[field]:
                tokens.setdefault(field, obj[field])

    _scan(data)
    for val in data.values():
        if isinstance(val, dict):
            _scan(val)
    return tokens


def extract_auth_request_headers(request_text):
    """Extract auth token values from request headers defined in AUTH_REQUEST_HEADERS.

    Returns a dict mapping header_name -> value.  For the Authorization header
    the scheme prefix (Bearer / Basic / Token) is stripped so only the credential
    value is stored.  Add new header names to AUTH_REQUEST_HEADERS to extend
    coverage.
    """
    found = {}
    for header in AUTH_REQUEST_HEADERS:
        match = re.search(rf"(?i){re.escape(header)}:\s*(.+?)\\r\\n", request_text)
        if match:
            value = match.group(1).strip()
            if header.lower() == "authorization":
                value = re.sub(r"^(?:Bearer|Basic|Token)\s+", "", value, flags=re.I)
            found[header] = value
    return found


def item_has_auth_identifiers(item):
    """Return True if the item carries any cookie, auth token, or CSRF field."""
    return bool(
        item.get("cookies_set")
        or item.get("auth_request_headers")
        or item.get("response_tokens")
        or item["hidden_fields"]
    )


# ---------------------------------------------------------------------------
# Item processing
# ---------------------------------------------------------------------------

def process_files(files):
    """Process all input files and return classified, deduplicated items.

    Items from multiple files are merged and deduplicated by request content
    hash, preserving the original fetch order (oldest first within each file).
    """
    all_pairs = []
    for filepath in files:
        try:
            pairs = extract_items_from_file(filepath)
            all_pairs.extend(pairs)
        except Exception as e:
            print(f"Warning: Failed to read {filepath}: {e}", file=sys.stderr)

    items = []
    seen_keys = set()
    now = datetime.now(timezone.utc)

    for req, resp, notes in all_pairs:
        dedup_key = hashlib.md5(req.encode()).hexdigest()
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        method_match = re.match(r"(\w+)\s+(\S+)\s+HTTP", req)
        if not method_match:
            continue
        method = method_match.group(1)
        path = method_match.group(2)

        status_match = re.match(r"HTTP/[\d.]+ (\d+)", resp)
        status = status_match.group(1) if status_match else "?"

        host_match = re.search(r"Host:\s*(.+?)\\r\\n", req)
        host = host_match.group(1).strip() if host_match else "unknown"

        dt = _parse_xml_time(notes) or parse_date_header(resp) or now

        cookies_set = parse_all_set_cookies(resp)
        cookies_sent = parse_cookie_header(req)

        location_match = re.search(r"Location:\s*(.+?)\\r\\n", resp)
        location = location_match.group(1).strip() if location_match else ""
        hidden_fields = extract_hidden_fields(resp)
        response_tokens = extract_response_body_tokens(resp)
        auth_request_headers = extract_auth_request_headers(req)

        body = ""
        if "\\r\\n\\r\\n" in req:
            body = req.split("\\r\\n\\r\\n", 1)[1]

        cred_params = extract_cred_params(body)
        category = classify_item(method, path, status, location, body)

        masked_creds = []
        for name, val in cred_params:
            if name.lower() in ("password", "passwd"):
                masked_creds.append({"name": name, "value": "****"})
            else:
                masked_creds.append({"name": name, "value": val})

        items.append(
            {
                "timestamp": dt.isoformat(),
                "time": dt.strftime("%H:%M:%S"),
                "date": dt.strftime("%Y-%m-%d"),
                "host": host,
                "method": method,
                "path": path,
                "status": status,
                "category": category,
                "location": location,
                "set_cookies_raw": [c["raw"] for c in cookies_set],
                "cookies_set": cookies_set,
                "cookies_sent": cookies_sent,
                "hidden_fields": [
                    {"name": n, "value": v} for n, v in hidden_fields
                ],
                "cred_params": masked_creds,
                "response_tokens": response_tokens,
                "auth_request_headers": auth_request_headers,
            }
        )

    return items


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(items, scope_desc, source_desc):
    """Generate a pre-formatted markdown report with ASCII sequence diagram."""

    STATIC_RE = re.compile(r'\.(gif|jpe?g|png|ico|css|woff2?|ttf|svg|js)(\?.*)?$', re.I)
    WSA = "web-security-academy.net"

    def is_visible(item):
        path = item["path"].split("?")[0]
        if STATIC_RE.search(path):
            return False
        if WSA in item["host"] and item["path"].startswith("/academyLabHeader"):
            return False
        return True

    def _display(value):
        return f"{value[:8]}...{value[-4:]}" if len(value) > 12 else value

    # Group by host, sort chronologically
    hosts = {}
    for item in items:
        hosts.setdefault(item["host"], []).append(item)
    for h in hosts:
        hosts[h].sort(key=lambda x: x["timestamp"])

    # Auth type classification
    has_csrf_tokens = any(hf for item in items for hf in item["hidden_fields"])
    has_mfa = any(item["category"] == "MFA Challenge" for item in items)
    has_oauth = any(item["category"] == "OAuth/SSO Callback" for item in items)
    has_response_tokens = any(item.get("response_tokens") for item in items)
    if has_oauth:
        auth_type = "OAuth/SSO-based authentication"
    elif has_mfa:
        auth_type = "Multi-factor authentication (MFA/2FA)"
    elif has_response_tokens:
        auth_type = "Token-based authentication (stateless / header token)"
    elif has_csrf_tokens:
        auth_type = "Form-based authentication with CSRF protection"
    else:
        auth_type = "Form-based authentication — no CSRF token detected"

    out = [
        f"**Source:** {source_desc}",
        f"**Scope:** {scope_desc} · {len(items)} items · {len(hosts)} host(s)",
        f"**Authentication type:** {auth_type}",
        "",
        "---",
    ]

    global_findings = []

    for host, host_items in hosts.items():
        visible = [i for i in host_items if is_visible(i)]
        if not visible:
            continue

        host_has_auth = any(item_has_auth_identifiers(i) for i in host_items)
        if not host_has_auth:
            continue

        out.append(f"\n## {host}")

        # ---- Cookie lifecycle — pass 1 ----
        # Register every non-'other' cookie set during this host's flow.
        cookie_order = []
        cookie_info = {}

        for item in host_items:
            for c in item.get("cookies_set", []):
                if c["kind"] == "other":
                    continue
                name = c["name"]
                if name not in cookie_info:
                    if item["category"] in ("Credential Submission", "Token Exchange"):
                        state = "Authenticated"
                    elif item["category"] == "Logout":
                        state = "Post-logout"
                    elif item["category"] == "MFA Challenge":
                        state = "Pre-2FA"
                    else:
                        state = "Pre-auth"
                    cookie_info[name] = {
                        "kind": c["kind"],
                        "value": c["value"],
                        "display": _display(c["value"]),
                        "set_on": item["path"],
                        "state": state,
                        "flags": c["flags"],
                        "count": 0,
                    }
                    cookie_order.append(name)

        # ---- Cookie lifecycle — pass 2 ----
        # Count requests that sent each registered cookie.
        for item in host_items:
            for name in item.get("cookies_sent", {}):
                if name in cookie_info:
                    cookie_info[name]["count"] += 1

        # Items that send a registered session/jwt cookie also appear in diagram
        registered_session_names = {
            n for n, info in cookie_info.items() if info["kind"] in ("session", "jwt")
        }
        diagram_items = [
            i for i in visible
            if item_has_auth_identifiers(i)
            or any(name in registered_session_names for name in i.get("cookies_sent", {}))
        ]

        # ---- Token lifecycle — pass 1 ----
        token_order = []
        token_info = {}

        for item in host_items:
            for field, value in item.get("response_tokens", {}).items():
                if field not in token_info:
                    token_info[field] = {
                        "value": value,
                        "display": _display(value),
                        "set_on": item["path"],
                        "count": 0,
                        "used_via": set(),
                    }
                    token_order.append(field)

        # ---- Token lifecycle — pass 2 ----
        for item in host_items:
            for header, value in item.get("auth_request_headers", {}).items():
                matched = False
                for field in token_order:
                    if token_info[field]["value"] == value:
                        token_info[field]["count"] += 1
                        token_info[field]["used_via"].add(header)
                        matched = True
                if not matched:
                    orphan_key = f"_orphan_{value[:16]}"
                    if orphan_key not in token_info:
                        token_info[orphan_key] = {
                            "value": value,
                            "display": _display(value),
                            "set_on": "(not captured in history)",
                            "count": 0,
                            "used_via": set(),
                        }
                        token_order.append(orphan_key)
                    token_info[orphan_key]["count"] += 1
                    token_info[orphan_key]["used_via"].add(header)

        # ---- Session Identifier Origins ----
        out += [
            "",
            "### Session Identifier First Seen",
            "",
            "| # | Identifier | Kind | Value | First Appeared In | Direction | State |",
            "|---|---|---|---|---|---|---|",
        ]

        origins = []
        csrf_seen = set()

        # Cookies (session, jwt, device) — in order first seen
        for name in cookie_order:
            info = cookie_info[name]
            if info["kind"] == "other":
                continue
            origins.append({
                "identifier": name,
                "kind": info["kind"],
                "display": info["display"],
                "first_seen": info["set_on"],
                "direction": "Response (`Set-Cookie`)",
                "state": info["state"],
            })

        # Response body tokens
        for field in token_order:
            if field.startswith("_orphan_"):
                continue
            info = token_info[field]
            origins.append({
                "identifier": field,
                "kind": "token",
                "display": info["display"],
                "first_seen": info["set_on"],
                "direction": "Response (body JSON)",
                "state": "—",
            })

        # CSRF hidden fields — first occurrence per field name
        for item in host_items:
            for hf in item["hidden_fields"]:
                if hf["name"] not in csrf_seen:
                    csrf_seen.add(hf["name"])
                    origins.append({
                        "identifier": hf["name"],
                        "kind": "csrf",
                        "display": _display(hf["value"]),
                        "first_seen": item["path"],
                        "direction": "Response (hidden field)",
                        "state": "Pre-auth",
                    })

        if origins:
            for i, o in enumerate(origins, 1):
                out.append(
                    f"| {i} | `{o['identifier']}` | {o['kind']} | `{o['display']}` "
                    f"| `{o['first_seen']}` | {o['direction']} | {o['state']} |"
                )
        else:
            out.append("No session identifiers detected.")

        # ---- Session & Cookie Identifiers ----
        if host_has_auth:
            out += ["", "### Session & Cookie Identifiers", ""]

            session_jwt = [
                (n, cookie_info[n]) for n in cookie_order
                if cookie_info[n]["kind"] in ("session", "jwt")
            ]
            device = [
                (n, cookie_info[n]) for n in cookie_order
                if cookie_info[n]["kind"] == "device"
            ]

            rows = session_jwt + device
            if rows:
                out.append("| # | Name | Kind | Flags | Set On | State | Requests |")
                out.append("|---|---|---|---|---|---|---|")
                for row_num, (name, info) in enumerate(rows, 1):
                    f = info["flags"]
                    flag_parts = []
                    if f.get("Secure"):
                        flag_parts.append("`Secure`")
                    if f.get("HttpOnly"):
                        flag_parts.append("`HttpOnly`")
                    ss = f.get("SameSite")
                    if ss:
                        emoji = " ⚠️" if ss == "None" else ""
                        flag_parts.append(f"`SameSite={ss}`{emoji}")
                    ma = f.get("Max-Age")
                    if ma:
                        flag_parts.append(f"`Max-Age={ma}`")
                    flags_str = " ".join(flag_parts) if flag_parts else "—"
                    out.append(
                        f"| {row_num} | `{name}` | {info['kind']} | {flags_str} "
                        f"| `{info['set_on']}` | {info['state']} | {info['count']} |"
                    )
            else:
                out.append("No session cookies observed.")

            # ---- Token Identifiers ----
            out += ["", "### Token Identifiers", ""]
            if token_order:
                out.append("| # | Field | Value | Issued On | Requests | Via Header |")
                out.append("|---|---|---|---|---|---|")
                for i, field in enumerate(token_order, 1):
                    info = token_info[field]
                    if field.startswith("_orphan_"):
                        display_field = (
                            " / ".join(sorted(info["used_via"])) if info["used_via"] else "token"
                        )
                    else:
                        display_field = field
                    via = (
                        ", ".join(f"`{h}`" for h in sorted(info["used_via"]))
                        if info["used_via"] else "—"
                    )
                    issued = (
                        info["set_on"] if info["set_on"].startswith("(")
                        else f"`{info['set_on']}`"
                    )
                    out.append(
                        f"| {i} | `{display_field}` | `{info['display']}` "
                        f"| {issued} | {info['count']} | {via} |"
                    )
            else:
                out.append("No response body tokens detected.")

            # ---- CSRF / Anti-Forgery Tokens ----
            out += ["", "### CSRF / Anti-Forgery Tokens", ""]
            csrf_rows = []

            # Hidden form fields
            for item in host_items:
                for hf in item["hidden_fields"]:
                    csrf_rows.append(("hidden field", hf["name"], hf["value"], item["path"]))

            # Set-Cookie CSRF tokens
            for name in cookie_order:
                if cookie_info[name]["kind"] == "csrf":
                    info = cookie_info[name]
                    csrf_rows.append(("Set-Cookie", name, info["value"], info["set_on"]))

            if csrf_rows:
                out.append("| Token Name | Mechanism | Value | Found In |")
                out.append("|---|---|---|---|")
                for mechanism, name, value, path in csrf_rows:
                    display = f"{value[:20]}..." if len(value) > 20 else value
                    out.append(
                        f"| `{name}` | {mechanism} | `{display}` | `{path}` |"
                    )
            else:
                out.append("No CSRF tokens detected.")

        # ---- Per-host findings ----
        CSRF_TOKEN_NAMES = ("csrf_token", "user_token", "_token", "authenticity_token")
        for item in host_items:
            if (
                item["method"] == "POST"
                and item["category"] not in (
                    "Credential Submission", "Token Exchange", "MFA Challenge"
                )
                and not any(
                    hf["name"].lower() in CSRF_TOKEN_NAMES
                    for hf in item["hidden_fields"]
                )
            ):
                global_findings.append(
                    ("High", "No CSRF protection",
                     f"`{item['method']} {item['path']}`")
                )

        if any(
            c["flags"].get("SameSite") == "None"
            for item in host_items
            for c in item.get("cookies_set", [])
        ):
            global_findings.append((
                "Medium", "`SameSite=None` on session cookie",
                "Cross-site requests carry the session — no browser CSRF barrier",
            ))

        for item in host_items:
            if item["category"] == "Credential Submission" and any(
                c["kind"] in ("session", "jwt")
                for c in item.get("cookies_set", [])
            ):
                global_findings.append((
                    "✓ Good", "Session rotation on login",
                    f"New session issued on `POST {item['path']}`",
                ))
                break

        sess_cookies = [
            c for item in host_items
            for c in item.get("cookies_set", [])
            if c["kind"] == "session"
        ]
        if sess_cookies and all(
            c["flags"].get("Secure") and c["flags"].get("HttpOnly")
            for c in sess_cookies
        ):
            global_findings.append((
                "✓ Good", "`Secure` + `HttpOnly` flags",
                "All session cookies — prevents sniffing and JS theft",
            ))

    # Deduplicate findings (keep first occurrence)
    seen_f: set = set()
    deduped = []
    for f in global_findings:
        key = f[:2]
        if key not in seen_f:
            seen_f.add(key)
            deduped.append(f)

    out += ["", "## Notable Findings", ""]
    if deduped:
        out.append("| Risk | Finding | Detail |")
        out.append("|---|---|---|")
        for risk, title, detail in deduped:
            out.append(f"| {risk} | **{title}** | {detail} |")
    else:
        out.append("No significant findings.")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Output modes
# ---------------------------------------------------------------------------

def summarize(items, last):
    """Print summary stats to stderr and JSON array to stdout."""
    if not items:
        print("NO_ITEMS_FOUND", file=sys.stderr)
        print("[]")
        return

    scope = f"last {last}" if last else "all"
    print(f"Scope    : {scope} items", file=sys.stderr)
    print(f"Returned : {len(items)} items", file=sys.stderr)

    categories = {}
    for item in items:
        cat = item["category"]
        categories[cat] = categories.get(cat, 0) + 1
    print(f"Categories: {categories}", file=sys.stderr)

    hosts = set(item["host"] for item in items)
    print(f"Hosts: {hosts}", file=sys.stderr)

    json.dump(items, sys.stdout, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Parse Burp HTTP History for authentication flows"
    )
    parser.add_argument(
        "files", nargs="*",
        help="Burp history files (XML, JSON, or raw text)"
    )
    parser.add_argument(
        "--last", "-n", type=int, default=0,
        help="Keep only the last N items in fetch order (0 = all, default: 0)",
    )
    parser.add_argument(
        "--report", action="store_true",
        help="Output a pre-formatted markdown report instead of JSON",
    )
    parser.add_argument(
        "--version", action="store_true",
        help="Print version and changelog, then exit",
    )
    args = parser.parse_args()

    if args.version:
        print(f"parse_burp_history.py v{VERSION}")
        print(CHANGELOG)
        return

    if not args.files:
        parser.error("at least one file is required")

    items = process_files(args.files)

    if args.last > 0:
        items = items[-args.last:]

    if args.report:
        if not items:
            print("NO_ITEMS_FOUND", file=sys.stderr)
            return
        scope_desc = f"last {args.last}" if args.last else "all"
        source_desc = (
            args.files[0] if len(args.files) == 1
            else f"{len(args.files)} files"
        )
        print(generate_report(items, scope_desc, source_desc))
    else:
        summarize(items, args.last)


if __name__ == "__main__":
    main()
