#!/usr/bin/env python3
"""
Parse Burp Suite HTTP History JSON output files.

Extracts authentication-related items, deduplicates across multiple result
files, classifies each item, and outputs structured JSON.

Usage:
    python3 parse_burp_history.py [--last N] file1.txt [file2.txt ...]

    --last N  Keep only the last N items (most recent in fetch order).
              Omit or use 0 to return all items.

Output: JSON array of classified authentication flow items to stdout.
        Summary stats to stderr.
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone


def extract_items_from_file(filepath):
    """Extract request/response pairs from a Burp MCP tool result file.

    Accepts two formats:
    - JSON array: [{"type": "text", "text": "..."}]  (auto-saved by system)
    - Raw text: item content written directly (manually saved inline results)
    """
    with open(filepath) as f:
        raw = f.read()

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

    # Logout
    if "logout" in path_lower or "signout" in path_lower or "sign-out" in path_lower:
        return "Logout"

    # Initial visit redirecting to login
    if (
        method == "GET"
        and path_lower in ("/", "/index.php", "/index.html", "/default.aspx")
        and status == "302"
        and "login" in location_lower
    ):
        return "Initial Visit / Redirect"

    # Login page load
    if method == "GET" and "login" in path_lower and status == "200":
        return "Login Page Load"

    # Credential submission
    if method == "POST" and ("login" in path_lower or "auth" in path_lower or "token" in path_lower):
        has_creds = bool(
            re.search(r"(username|password|email|user|passwd|credential)", body, re.I)
        )
        if has_creds or "login" in path_lower:
            return "Credential Submission"
        if "token" in path_lower:
            return "Token Exchange"

    # MFA challenge
    if method in ("GET", "POST") and re.search(r"(mfa|2fa|otp|verify|challenge)", path_lower):
        return "MFA Challenge"

    # OAuth/SSO callback
    if re.search(r"(callback|redirect_uri|authorize)", path_lower):
        return "OAuth/SSO Callback"

    # Static assets
    if re.search(r"\.(css|js|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot)$", path_lower):
        return "Static Asset"

    # Post-auth page (authenticated GET returning 200)
    if method == "GET" and status == "200" and "login" not in path_lower:
        return "Post-Auth Page Load"

    # Redirect after login
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
        # Dedup by request content hash — handles the same item appearing in
        # multiple result files due to overlapping regex patterns.
        dedup_key = hashlib.md5(req.encode()).hexdigest()
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        # Extract method and path
        method_match = re.match(r"(\w+)\s+(\S+)\s+HTTP", req)
        if not method_match:
            continue
        method = method_match.group(1)
        path = method_match.group(2)

        # Status code
        status_match = re.match(r"HTTP/[\d.]+ (\d+)", resp)
        status = status_match.group(1) if status_match else "?"

        # Host
        host_match = re.search(r"Host:\s*(.+?)\\r\\n", req)
        host = host_match.group(1).strip() if host_match else "unknown"

        # Timestamp — use Date header if present, otherwise script invocation time
        dt = parse_date_header(resp) or now

        # Extract details
        set_cookies = extract_set_cookies(resp)
        cookies_sent = extract_cookie_header(req)
        location_match = re.search(r"Location:\s*(.+?)\\r\\n", resp)
        location = location_match.group(1).strip() if location_match else ""
        hidden_fields = extract_hidden_fields(resp)

        body = ""
        if "\\r\\n\\r\\n" in req:
            body = req.split("\\r\\n\\r\\n", 1)[1]

        cred_params = extract_cred_params(body)
        category = classify_item(method, path, status, location, set_cookies, body)

        # Session IDs
        session_ids_sent = extract_session_ids(cookies_sent)
        session_ids_set = {}
        cookie_flags = {}
        for sc in set_cookies:
            sids = extract_session_ids(sc)
            session_ids_set.update(sids)
            for sid_name in sids:
                cookie_flags[sid_name] = extract_cookie_flags(sc)

        # Mask password values
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
            }
        )

    return items


def summarize(items, last):
    """Print a human-readable summary to stderr and JSON to stdout."""
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
    parser.add_argument("files", nargs="+", help="Burp MCP tool result JSON files")
    parser.add_argument(
        "--last", "-n", type=int, default=0,
        help="Keep only the last N items in fetch order (0 = all, default: 0)"
    )
    args = parser.parse_args()

    items = process_files(args.files)

    if args.last > 0:
        items = items[-args.last:]

    summarize(items, args.last)


if __name__ == "__main__":
    main()
