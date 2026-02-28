# Burp Authentication Mapper

Map and document authentication flows from Burp Suite HTTP History. Produce an ASCII sequence diagram, session tracking, and CSRF token analysis.

## Workflow

### Step 0: Ask for Time Window

Before fetching any history, use the AskUserQuestion tool to prompt the user to select a time window. The tool supports a maximum of 4 options, so use exactly these four:

- Last 5 minutes
- Last 15 minutes
- Last 30 minutes
- Last 1 hour

Map the selection to the appropriate filter: `5m` → `--minutes 5`, `15m` → `--minutes 15`, `30m` → `--minutes 30`, `1h` → `--hours 1`.

### Step 1: Fetch History from Burp

Call `get_proxy_http_history_regex` with a single combined regex to minimize overlap:

```
regex: (?i)(login|signin|authenticate|auth|token|session|username|password|Set-Cookie|PHPSESSID|JSESSIONID|csrf|user_token|logout|signout)
count: 100
offset: 0
```

If results exceed the token limit and are saved to a file, proceed to Step 2.

### Step 2: Process with Script

Run `scripts/parse_burp_history.py` to filter, deduplicate, and classify items:

```bash
python3 scripts/parse_burp_history.py [--minutes M | --hours H | --all] <result_file(s)>
```

Map the user's selection to the script flag: `5m` → `--minutes 5`, `1h` → `--hours 1`, "All history" → `--all`.

The script outputs structured JSON to stdout and summary stats to stderr. If the script reports `NO_ITEMS_FOUND` on stderr, inform the user of the history date range and suggest a wider time window.

If results are small enough to process inline (not saved to file), extract and classify items directly using the patterns in `references/auth_patterns.md`.

After the script completes, check the file sizes and then delete the temporary file(s):

```bash
du -sh <result_file(s)>
rm <result_file(s)>
```

Report the total size freed to the user.

### Step 3: Generate Output

Using the classified items (from the script JSON or inline processing), generate these sections in order. Refer to `references/example_output.md` for exact formatting.

**Header:** Target host, time window, and authentication type classification.

**Section 1 — ASCII Sequence Diagram:** Show the Browser/Server interaction flow as a two-column diagram — do NOT include a Burp Proxy column. Refer to `references/example_output.md` for the exact diagram format. Exclude any requests whose path ends with the following extensions: `gif`, `jpg`, `png`, `ico`, `css`, `woff`, `woff2`, `ttf`, `svg`. If the target host contains `web-security-academy.net`, also exclude `GET /academyLabHeader` requests. Mask password values with `****`.

**Section 2 — Session Identifiers:** Table of all unique session IDs with their lifecycle state (pre-auth, authenticated, post-logout), request count, and context.

**Section 3 — CSRF / Anti-Forgery Tokens:** Table of tokens found in hidden fields and where they were submitted.

## Edge Case Handling

- **Large results saved to file:** Use the `parse_burp_history.py` script with the file path(s)
- **Empty time window:** Report the actual history date range to the user and suggest widening the window or using no time argument
- **No Burp MCP connection:** If `get_proxy_http_history_regex` fails, inform the user to verify the Burp MCP server is running and connected
- **Non-DVWA targets:** The skill works with any web application — classification and patterns are framework-agnostic
- **Multiple hosts in history:** Group output by host if multiple targets are detected

## Resources

- `scripts/parse_burp_history.py` — Deterministic parser for Burp history JSON. Handles time filtering, deduplication, item classification, session ID extraction, and credential masking. Run directly without loading into context.
- `references/auth_patterns.md` — Regex patterns, classification rules, extraction checklists, and authentication flow type reference.
- `references/security_checklist.md` — Full security evaluation criteria organized by category (transport, session, CSRF, credentials, errors, MFA, brute force, logout).
- `references/example_output.md` — Real DVWA example output for consistent formatting reference.
