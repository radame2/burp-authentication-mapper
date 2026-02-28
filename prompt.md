# Burp Authentication Mapper

Map and document authentication flows from Burp Suite HTTP History. Produce an ASCII sequence diagram, session tracking, CSRF token analysis, and security observations.

## Argument Parsing

Parse the optional time parameter from the user's request:

- `5m` — last 5 minutes
- `30m` — last 30 minutes
- `1h` — last 1 hour
- `2h` — last 2 hours
- No argument — scan the entire HTTP History

Extract the numeric value and unit suffix (`m` for minutes, `h` for hours).

## Workflow

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

Map the time argument: `5m` becomes `--minutes 5`, `1h` becomes `--hours 1`, no argument becomes `--all`.

The script outputs structured JSON to stdout and summary stats to stderr. If the script reports `NO_ITEMS_FOUND` on stderr, inform the user of the history date range and suggest a wider time window.

If results are small enough to process inline (not saved to file), extract and classify items directly using the patterns in `references/auth_patterns.md`.

### Step 3: Generate Output

Using the classified items (from the script JSON or inline processing), generate these sections in order. Refer to `references/example_output.md` for exact formatting.

**Header:** Target host, time window, and authentication type classification.

**Section 1 — ASCII Sequence Diagram:** Show the Browser/Proxy/Server interaction flow. Refer to `references/example_output.md` for the exact diagram format. Group static assets into single steps. Mask password values with `****`.

**Section 2 — Session Identifiers:** Table of all unique session IDs with their lifecycle state (pre-auth, authenticated, post-logout), request count, and context.

**Section 3 — CSRF / Anti-Forgery Tokens:** Table of tokens found in hidden fields and where they were submitted.

**Section 4 — Security Observations:** Evaluate the authentication flow against `references/security_checklist.md`. Present as a table with Finding, Detail, and Risk/Rating columns. Include both positive (GOOD) and negative findings.

**Section 5 — Authentication Type Classification:** Classify using the flow types documented in `references/auth_patterns.md` (form-based, token-based, MFA, SSO, Basic/Digest).

## Edge Case Handling

- **Large results saved to file:** Use the `parse_burp_history.py` script with the file path(s)
- **Empty time window:** Report the actual history date range to the user and suggest widening the window or using no time argument
- **No Burp MCP connection:** If `get_proxy_http_history_regex` fails, inform the user to verify the Burp MCP server is running and connected
- **Non-DVWA targets:** This workflow works with any web application — classification and patterns are framework-agnostic
- **Multiple hosts in history:** Group output by host if multiple targets are detected

## Resources

- `scripts/parse_burp_history.py` — Deterministic parser for Burp history JSON. Handles time filtering, deduplication, item classification, session ID extraction, and credential masking. Run directly without loading into context.
- `references/auth_patterns.md` — Regex patterns, classification rules, extraction checklists, and authentication flow type reference.
- `references/security_checklist.md` — Full security evaluation criteria organized by category (transport, session, CSRF, credentials, errors, MFA, brute force, logout).
- `references/example_output.md` — Real DVWA example output for consistent formatting reference.
