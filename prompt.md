# Burp Authentication Mapper

Map and document authentication flows from Burp Suite HTTP History. Produce an ASCII sequence diagram, session tracking, and CSRF token analysis.

## Workflow

### Step 0: Ask for Scope

Before fetching any history, use the AskUserQuestion tool to ask how many recent requests to analyse. Use exactly these four options:

- Last 25 requests
- Last 50 requests
- Last 100 requests
- All in history

Map the selection to the `--last` flag: "Last 25" → `--last 25`, "Last 50" → `--last 50`, "Last 100" → `--last 100`, "All in history" → omit `--last` (returns everything).

### Step 1: Download Full History to Local Files

Fetch the **entire** Burp HTTP History by paginating through `get_proxy_http_history` with `count: 200`. Never process results inline — always save every page to a local file first.

**Pagination loop:**

1. Call `get_proxy_http_history` with `count: 200, offset: 0`
2. Save the result to a local file (see rules below)
3. If the result says `"Reached end of items"` — stop
4. Otherwise increment offset by 200 and repeat from step 1

**File-saving rules (apply after every call):**

- **Auto-saved (result exceeded token limit):** The system has already saved it; note the returned file path.
- **Returned inline:** Use the Write tool to save the raw result text to `/tmp/burp_history_pNNN.txt` (e.g. `p001`, `p002`, …), writing the content exactly as returned with no JSON wrapping.

Collect every file path (auto-saved or manually written). Proceed to Step 2 once `"Reached end of items"` is returned.

### Step 2: Process with Script

Run `scripts/parse_burp_history.py` once, passing all collected file paths. The script merges and deduplicates across files automatically:

```bash
python3 scripts/parse_burp_history.py [--last N] <file1> [file2 ...]
```

Map the user's scope to `--last`: "Last 25" → `--last 25`, "All in history" → omit the flag.

The script outputs structured JSON to stdout and summary stats to stderr. If the script reports `NO_ITEMS_FOUND` on stderr, inform the user.

After the script completes, check file sizes and delete all temporary files:

```bash
du -sh <file(s)>
rm <file(s)>
```

Report the total size freed to the user.

### Step 3: Generate Output

Using the classified items from the script JSON output, generate these sections in order. Refer to `references/example_output.md` for exact formatting.

**Header:** Target host, scope selected, and authentication type classification.

**Section 1 — ASCII Sequence Diagram:** Show the Browser/Server interaction flow as a two-column diagram — do NOT include a Burp Proxy column. Refer to `references/example_output.md` for the exact diagram format. Exclude any requests whose path ends with the following extensions: `gif`, `jpg`, `png`, `ico`, `css`, `woff`, `woff2`, `ttf`, `svg`. If the target host contains `web-security-academy.net`, also exclude `GET /academyLabHeader` requests. Mask password values with `****`.

**Section 2 — Session Identifiers:** Table of all unique session IDs with their lifecycle state (pre-auth, authenticated, post-logout), request count, and context.

**Section 3 — CSRF / Anti-Forgery Tokens:** Table of tokens found in hidden fields and where they were submitted.

## Edge Case Handling

- **No items found:** Inform the user and suggest selecting "All in history" scope
- **No Burp MCP connection:** If `get_proxy_http_history` fails, inform the user to verify the Burp MCP server is running and connected
- **Non-DVWA targets:** The skill works with any web application — classification and patterns are framework-agnostic
- **Multiple hosts in history:** Group output by host if multiple targets are detected

## Resources

- `scripts/parse_burp_history.py` — Deterministic parser for Burp history result files. Accepts multiple files, merges and deduplicates by request hash, classifies items, extracts session IDs and credentials. Handles both auto-saved (JSON array) and manually written (raw text) file formats. Run directly without loading into context.
- `references/auth_patterns.md` — Regex patterns, classification rules, extraction checklists, and authentication flow type reference.
- `references/security_checklist.md` — Full security evaluation criteria organized by category (transport, session, CSRF, credentials, errors, MFA, brute force, logout).
- `references/example_output.md` — Real DVWA example output for consistent formatting reference.
