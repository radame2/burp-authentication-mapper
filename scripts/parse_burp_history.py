#!/usr/bin/env python3
"""
Parse Burp Suite HTTP History files.

Extracts authentication-related items, deduplicates across multiple result
files, classifies each item, and outputs either structured JSON or a
pre-formatted markdown report.

Usage:
    python3 parse_burp_history.py [--last N] [--report] file1 [file2 ...]

    --last N    Keep only the last N items (most recent in fetch order).
                Omit or use 0 to return all items.
    --report    Output a pre-formatted markdown report (sequence diagram,
                session table, CSRF table, findings) instead of JSON.

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


# ---------------------------------------------------------------------------
# Configurable token registries  (extend these lists to support new tokens)
# ---------------------------------------------------------------------------

# JSON field names to search for in response bodies (top-level and one level
# deep inside nested objects).  Add new field names here as APIs evolve.
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

# HTTP request header names that carry an auth token.  Matched
# case-insensitively.  For "Authorization", the scheme prefix
# (Bearer / Basic / Token) is stripped automatically.  Add new header
# names here as custom APIs introduce them.
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
    # Remove timezone abbreviation (EST, UTC, GMT, BST, …)
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

        # Normalise to the escaped form the rest of the script expects
        req_text = req_text.replace("\r\n", "\\r\\n").replace("\n", "\\r\\n")
        resp_text = resp_text.replace("\r\n", "\\r\\n").replace("\n", "\\r\\n")

        pairs.append((req_text, resp_text, time_str))
    # XML export is newest-first; reverse so oldest-first order is preserved
    # through the timestamp sort (stable sort keeps relative order within a second)
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


def classify_item(method, path, status, location, set_cookies, body):
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


def extract_set_cookies(response_text):
    """Extract all Set-Cookie header values from a response."""
    return re.findall(r"Set-Cookie:\s*(.+?)\\r\\n", response_text)


def extract_cookie_header(request_text):
    """Extract the Cookie header value from a request."""
    match = re.search(r"Cookie:\s*(.+?)\\r\\n", request_text)
    return match.group(1) if match else ""


def extract_session_ids(cookie_string):
    """Extract known session ID values from a cookie string."""
    ids = {}
    for pattern, name in [
        (r"PHPSESSID=([a-f0-9]+)", "PHPSESSID"),
        (r"JSESSIONID=([A-Fa-f0-9]+)", "JSESSIONID"),
        (r"ASP\.NET_SessionId=([^\s;]+)", "ASP.NET_SessionId"),
        (r"connect\.sid=([^\s;]+)", "connect.sid"),
        (r"\bsession=([^\s;,]+)", "session"),
    ]:
        match = re.search(pattern, cookie_string)
        if match:
            ids[name] = match.group(1)
    return ids


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
    # When the body was captured via regex from an MCP-format JSON file the
    # quotes inside the JSON body are still escaped as \" — unescape them so
    # json.loads can parse the object correctly.  This is a no-op for bodies
    # that already contain literal quote characters (e.g. XML-export format).
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


def extract_cookie_flags(set_cookie_value):
    """Extract security flags from a Set-Cookie header value."""
    flags = {}
    flags["HttpOnly"] = "HttpOnly" in set_cookie_value
    flags["Secure"] = "Secure" in set_cookie_value
    samesite = re.search(r"SameSite=(\w+)", set_cookie_value)
    flags["SameSite"] = samesite.group(1) if samesite else None
    maxage = re.search(r"Max-Age=(\d+)", set_cookie_value)
    flags["Max-Age"] = int(maxage.group(1)) if maxage else None
    domain = re.search(r"[Dd]omain=([^;\s]+)", set_cookie_value)
    flags["Domain"] = domain.group(1) if domain else None
    path = re.search(r"[Pp]ath=([^;\s]+)", set_cookie_value)
    flags["Path"] = path.group(1) if path else None
    return flags


def item_has_auth_identifiers(item):
    """Return True if the item carries any session cookie, auth token, or CSRF field.

    Used to decide whether a diagram step is worth showing on hosts that have
    at least some auth traffic, and to decide whether to render the three
    identifier sections at all for a given host.
    """
    return bool(
        item['session_ids_sent']
        or item['session_ids_set']
        or item['set_cookies_raw']
        or item.get('auth_request_headers')
        or item.get('response_tokens')
        or item['hidden_fields']
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

        # Timestamp: Burp XML export time (notes) > HTTP Date header > now
        dt = _parse_xml_time(notes) or parse_date_header(resp) or now

        set_cookies = extract_set_cookies(resp)
        cookies_sent = extract_cookie_header(req)
        location_match = re.search(r"Location:\s*(.+?)\\r\\n", resp)
        location = location_match.group(1).strip() if location_match else ""
        hidden_fields = extract_hidden_fields(resp)
        response_tokens = extract_response_body_tokens(resp)
        auth_request_headers = extract_auth_request_headers(req)

        body = ""
        if "\\r\\n\\r\\n" in req:
            body = req.split("\\r\\n\\r\\n", 1)[1]

        cred_params = extract_cred_params(body)
        category = classify_item(method, path, status, location, set_cookies, body)

        session_ids_sent = extract_session_ids(cookies_sent)
        session_ids_set = {}
        cookie_flags = {}
        for sc in set_cookies:
            sids = extract_session_ids(sc)
            session_ids_set.update(sids)
            for sid_name in sids:
                cookie_flags[sid_name] = extract_cookie_flags(sc)

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
                "set_cookies_raw": set_cookies,
                "session_ids_set": session_ids_set,
                "session_ids_sent": session_ids_sent,
                "cookie_flags": cookie_flags,
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
    WSA = 'web-security-academy.net'

    def is_visible(item):
        path = item['path'].split('?')[0]
        if STATIC_RE.search(path):
            return False
        if WSA in item['host'] and item['path'].startswith('/academyLabHeader'):
            return False
        return True

    def pick_session(id_dict, raw_cookies):
        """Return the first session ID value from a parsed dict or raw Set-Cookie list."""
        if id_dict.get('session'):
            return id_dict['session']
        for val in id_dict.values():
            return val
        for sc in (raw_cookies or []):
            m = re.search(r'\bsession=([^\s;,]+)', sc, re.I)
            if m:
                return m.group(1)
        return None

    # Group by host, sort chronologically
    hosts = {}
    for item in items:
        hosts.setdefault(item['host'], []).append(item)
    for h in hosts:
        hosts[h].sort(key=lambda x: x['timestamp'])

    # Auth type classification
    has_csrf_tokens = any(hf for item in items for hf in item['hidden_fields'])
    has_mfa = any(item['category'] == 'MFA Challenge' for item in items)
    has_oauth = any(item['category'] == 'OAuth/SSO Callback' for item in items)
    has_response_tokens = any(item.get('response_tokens') for item in items)
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

        # Skip hosts that have no auth identifiers at all — nothing meaningful
        # to show for them (no tokens, cookies, or CSRF fields anywhere).
        host_has_auth = any(item_has_auth_identifiers(i) for i in host_items)
        if not host_has_auth:
            continue

        # Filter the diagram to only steps that carry at least one identifier.
        diagram_items = [i for i in visible if item_has_auth_identifiers(i)]

        out.append(f"\n## {host}")

        # Build session lifecycle — two passes so counts are correct regardless
        # of whether items arrived chronologically or newest-first.
        sess_order = []    # session IDs in first-seen order
        sess_info = {}     # sid -> {state, set_on, flags, count}

        # Pass 1: register every session that was set in a response
        for item in host_items:
            sid = pick_session(item['session_ids_set'], item['set_cookies_raw'])
            if sid and sid not in sess_info:
                if item['category'] in ('Credential Submission', 'Token Exchange'):
                    state = 'Authenticated'
                elif item['category'] == 'Logout':
                    state = 'Post-logout'
                elif item['category'] == 'MFA Challenge':
                    state = 'Pre-2FA'
                else:
                    state = 'Pre-auth'
                flags_raw = next(
                    (sc for sc in item['set_cookies_raw']
                     if re.search(r'\bsession=', sc, re.I)
                     or any(k in sc for k in ('PHPSESSID', 'JSESSIONID'))),
                    ""
                )
                sess_info[sid] = {
                    'state': state,
                    'set_on': item['path'],
                    'flags': flags_raw,
                    'count': 0,
                }
                sess_order.append(sid)

        # Pass 2: count how many requests each session was sent with
        for item in host_items:
            sent = pick_session(item['session_ids_sent'], [])
            if sent and sent in sess_info:
                sess_info[sent]['count'] += 1

        # Token lifecycle — pass 1: register every token issued in a response body
        token_order = []   # field names in first-seen order
        token_info = {}    # field -> {value, display, set_on, count, used_via}

        for item in host_items:
            for field, value in item.get('response_tokens', {}).items():
                if field not in token_info:
                    display = f"{value[:8]}...{value[-4:]}" if len(value) > 12 else value
                    token_info[field] = {
                        'value': value,
                        'display': display,
                        'set_on': item['path'],
                        'count': 0,
                        'used_via': set(),
                    }
                    token_order.append(field)

        # Token lifecycle — pass 2: count requests that carry each token.
        # If a token appears in a request header but was not found in any captured
        # response body, register it as an orphaned entry so it still appears in
        # the Token Identifiers table (origin marked as "not captured in history").
        for item in host_items:
            for header, value in item.get('auth_request_headers', {}).items():
                matched = False
                for field in token_order:
                    if token_info[field]['value'] == value:
                        token_info[field]['count'] += 1
                        token_info[field]['used_via'].add(header)
                        matched = True
                if not matched:
                    # Orphaned token — seen in request headers, origin not captured
                    orphan_key = f"_orphan_{value[:16]}"
                    if orphan_key not in token_info:
                        display = f"{value[:8]}...{value[-4:]}" if len(value) > 12 else value
                        token_info[orphan_key] = {
                            'value': value,
                            'display': display,
                            'set_on': '(not captured in history)',
                            'count': 0,
                            'used_via': set(),
                        }
                        token_order.append(orphan_key)
                    token_info[orphan_key]['count'] += 1
                    token_info[orphan_key]['used_via'].add(header)

        # ---- ASCII Sequence Diagram ----
        L = 52  # left column width
        out += [
            "",
            "### Sequence Diagram",
            "",
            "```",
            f"{'Browser':<{L}}Server",
            f"  |{' ' * (L - 3)}|",
        ]

        for step, item in enumerate(diagram_items, 1):
            # Request annotations
            req_lines = [f"{step}. {item['method']} {item['path']}"]

            sent = pick_session(item['session_ids_sent'], [])
            if sent:
                req_lines.append(f"  Cookie: session={sent[:8]}...{sent[-4:]}")

            for header, value in item.get('auth_request_headers', {}).items():
                display = f"{value[:8]}...{value[-4:]}" if len(value) > 12 else value
                req_lines.append(f"  {header}: {display}")

            for cp in item['cred_params']:
                req_lines.append(f"  {cp['name']}={cp['value']}")

            for line in req_lines:
                out.append(f"  |  {line:<{L - 5}}|")
            out.append(f"  |{'-' * (L - 4)}>|")

            # Response annotations
            resp_lines = []
            if item['location']:
                resp_lines.append(f"{item['status']} Found -> {item['location']}")
            else:
                resp_lines.append(f"{item['status']} OK")

            set_sid = pick_session(item['session_ids_set'], item['set_cookies_raw'])
            if set_sid:
                resp_lines.append(f"Set-Cookie: session={set_sid[:8]}...{set_sid[-4:]}")
                if item['category'] in ('Credential Submission', 'Token Exchange') and sent:
                    resp_lines.append("(session rotated on login)")

            for field, value in item.get('response_tokens', {}).items():
                display = f"{value[:8]}...{value[-4:]}" if len(value) > 12 else value
                resp_lines.append(f"token ({field}): {display}")

            for hf in item['hidden_fields']:
                resp_lines.append(f"Hidden: {hf['name']}={hf['value'][:16]}...")

            for line in resp_lines:
                out.append(f"  |  {line:<{L - 5}}|")
            out.append(f"  |<{'-' * (L - 4)}|")
            out.append(f"  |{' ' * (L - 3)}|")

        out.append("```")

        # ---- Session Identifiers / Token Identifiers / CSRF ----
        # Only rendered when the host has at least one auth identifier; if every
        # request and response for this host is unauthenticated these three
        # sections are suppressed entirely to keep the report clean.
        if host_has_auth:
            # Session Identifiers
            out += ["", "### Session Identifiers", ""]
            if sess_order:
                out.append("| # | session | State | Set On | Requests |")
                out.append("|---|---|---|---|---|")
                for i, sid in enumerate(sess_order, 1):
                    info = sess_info[sid]
                    out.append(
                        f"| {i} | `{sid}` | {info['state']} "
                        f"| `{info['set_on']}` | {info['count']} |"
                    )

                first_flags = sess_info[sess_order[0]]['flags']
                flag_parts = []
                if 'Secure' in first_flags:
                    flag_parts.append('`Secure` ✓')
                if 'HttpOnly' in first_flags:
                    flag_parts.append('`HttpOnly` ✓')
                m = re.search(r'SameSite=(\w+)', first_flags)
                if m:
                    val = m.group(1)
                    emoji = '⚠️' if val == 'None' else ('✓' if val == 'Strict' else '~')
                    flag_parts.append(f'`SameSite={val}` {emoji}')
                if flag_parts:
                    out.append(f"\n**Cookie flags:** {' · '.join(flag_parts)}")
            else:
                out.append("No session cookies observed.")

            # Token Identifiers
            out += ["", "### Token Identifiers", ""]
            if token_order:
                out.append("| # | Field | Value | Issued On | Requests | Via Header |")
                out.append("|---|---|---|---|---|---|")
                for i, field in enumerate(token_order, 1):
                    info = token_info[field]
                    # For orphaned tokens, derive the field label from the headers
                    # that carried it (known only after pass 2 completes).
                    if field.startswith("_orphan_"):
                        display_field = " / ".join(sorted(info['used_via'])) if info['used_via'] else "token"
                    else:
                        display_field = field
                    via = ", ".join(f"`{h}`" for h in sorted(info['used_via'])) if info['used_via'] else "—"
                    issued = info['set_on'] if info['set_on'].startswith('(') else f"`{info['set_on']}`"
                    out.append(
                        f"| {i} | `{display_field}` | `{info['display']}` "
                        f"| {issued} | {info['count']} | {via} |"
                    )
            else:
                out.append("No response body tokens detected.")

            # CSRF / Anti-Forgery Tokens
            out += ["", "### CSRF / Anti-Forgery Tokens", ""]
            csrf_pairs = [(item, hf) for item in host_items for hf in item['hidden_fields']]
            if csrf_pairs:
                out.append("| Token Name | Value | Found In | Submitted In |")
                out.append("|---|---|---|---|")
                for item, hf in csrf_pairs:
                    out.append(
                        f"| `{hf['name']}` | `{hf['value'][:20]}` "
                        f"| `{item['path']}` (hidden) | — |"
                    )
            else:
                out.append("No CSRF tokens detected.")

        # ---- Per-host findings ----
        CSRF_TOKEN_NAMES = ('csrf_token', 'user_token', '_token', 'authenticity_token')
        for item in host_items:
            if (
                item['method'] == 'POST'
                and item['category'] not in (
                    'Credential Submission', 'Token Exchange', 'MFA Challenge'
                )
                and not any(
                    hf['name'].lower() in CSRF_TOKEN_NAMES
                    for hf in item['hidden_fields']
                )
            ):
                global_findings.append(
                    ('High', 'No CSRF protection',
                     f"`{item['method']} {item['path']}`")
                )

        if any('SameSite=None' in sc for item in host_items for sc in item['set_cookies_raw']):
            global_findings.append((
                'Medium', '`SameSite=None` on session cookie',
                'Cross-site requests carry the session — no browser CSRF barrier',
            ))

        for item in host_items:
            if item['category'] == 'Credential Submission' and item['set_cookies_raw']:
                global_findings.append((
                    '✓ Good', 'Session rotation on login',
                    f"New session issued on `POST {item['path']}`",
                ))
                break

        sess_cookies = [
            sc for item in host_items for sc in item['set_cookies_raw']
            if re.search(r'\bsession=', sc, re.I)
        ]
        if sess_cookies and all(
            'Secure' in sc and 'HttpOnly' in sc for sc in sess_cookies
        ):
            global_findings.append((
                '✓ Good', '`Secure` + `HttpOnly` flags',
                'All session cookies — prevents sniffing and JS theft',
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
    parser.add_argument("files", nargs="+", help="Burp history files (XML, JSON, or raw text)")
    parser.add_argument(
        "--last", "-n", type=int, default=0,
        help="Keep only the last N items in fetch order (0 = all, default: 0)",
    )
    parser.add_argument(
        "--report", action="store_true",
        help="Output a pre-formatted markdown report instead of JSON",
    )
    args = parser.parse_args()

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
