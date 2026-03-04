# Burp Authentication Mapper

Map and document authentication flows from Burp Suite HTTP History. Produce an ASCII sequence diagram, session tracking, and CSRF token analysis.

## Workflow

### Step 0: Ask for Input Source and Scope

Use a **single** AskUserQuestion with these four options to select both source and scope in one step:

- **Live — Last 50 requests** — fetch the 50 most recent items from the connected Burp MCP server
- **Live — Last 100 requests** — fetch the 100 most recent items
- **Live — All in history** — fetch the entire proxy history
- **Local file** — analyse a Burp history XML file already saved on disk

**If a "Live" option is selected:**

Map to the `--last` flag: "Last 50" → `--last 50`, "Last 100" → `--last 100`, "All in history" → omit `--last`.

Continue to **Step 1**.

**If "Local file" is selected:**

Use a second AskUserQuestion to ask for the filename. Present the question with the instruction that the user should type the filename or full path using the "Other" field (e.g. `burp_history.xml`, `/home/kali/exports/session.xml`).

If the path starts with `/` or `~/`, expand `~` and check existence directly with `test -f`. Otherwise search with Bash `find` starting from the home directory and `/tmp`. If the file is not found, inform the user and stop.

Once the file is located, skip **Step 1** entirely and proceed directly to **Step 2**, passing the located file path.

### Step 1: Download Full History to Local Files

*(Skip this step if the user selected "Local file" in Step 0.)*

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

Run `scripts/parse_burp_history.py` once with the `--report` flag, passing all collected file paths:

```bash
python3 scripts/parse_burp_history.py --report [--last N] <file1> [file2 ...]
```

- **Live Burp History mode:** apply `--last N` as mapped from Step 0. Pass all paginated `/tmp` files.
- **Local file mode:** omit `--last`. Pass the located file path directly. Do not delete the file after processing (it belongs to the user).

The script outputs a fully-formatted markdown report to stdout (sequence diagrams, session tables, CSRF table, findings). If the script prints `NO_ITEMS_FOUND` to stderr, inform the user.

**Live Burp History only** — after the script completes, check file sizes and delete all temporary files:

```bash
du -sh <file(s)>
rm <file(s)>
```

Report the total size freed to the user.

### Step 3: Display Output

Output the script's stdout verbatim. Do not reformat or regenerate any section — the script has already produced the complete report. Prepend a one-line target/date context header if it adds useful orientation for the user.

## Edge Case Handling

- **No items found:** Inform the user and suggest selecting "All in history" scope or verifying the local file contains Burp history data
- **Local file not found:** Inform the user the file could not be located and ask them to verify the filename or provide the full path
- **No Burp MCP connection:** If `get_proxy_http_history` fails, inform the user to verify the Burp MCP server is running and connected
- **Non-DVWA targets:** The skill works with any web application — classification and patterns are framework-agnostic
- **Multiple hosts in history:** Group output by host if multiple targets are detected

## Script Location

`scripts/parse_burp_history.py` — run via Bash in Step 2. Do not read into context.
