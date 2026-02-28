# burp-authentication-mapper

An AI workflow that maps authentication flows from Burp Suite HTTP History into structured documentation — including an ASCII sequence diagram, session tracking, CSRF token analysis, and security observations.

## Example Output

See [`references/example_output.md`](references/example_output.md) for a real mapping of DVWA's authentication flow.

## Requirements

- **Burp Suite** with the [Burp MCP server](https://github.com/PortSwigger/mcp-server) running and connected
- **Python 3** (for processing large history results)
- **Claude Code** or **Gemini CLI** (see platform setup below)

## Usage

Ask your AI assistant to map your authentication flow. You can optionally scope the analysis to a recent time window:

```
Map my authentication flow from the last 5 minutes
Map the authentication flow from the last hour
Map the full authentication history
```

Supported time arguments: `5m`, `30m`, `1h`, `2h`, or no argument for the full history.

## Platform Setup

### Claude Code

Install the skill from the `platforms/claude/` directory:

```bash
cp platforms/claude/burp-authentication-mapper.zip ~/.claude/skills/
```

Restart Claude Code. The skill is then available as:

```
/burp-authentication-mapper
/burp-authentication-mapper 30m
/burp-authentication-mapper 1h
```

### Gemini CLI

Copy the required files into a working directory and run `gemini` from there:

```bash
git clone https://github.com/YOUR_USERNAME/burp-authentication-mapper
cd burp-authentication-mapper
cp platforms/gemini/GEMINI.md .
```

Then start Gemini CLI from that directory:

```bash
gemini
```

Gemini will automatically load `GEMINI.md` and the workflow will be available via natural language requests.

## Repository Structure

```
burp-authentication-mapper/
├── prompt.md                        # Canonical workflow — source of truth for all platforms
├── scripts/
│   └── parse_burp_history.py        # Standalone Python parser for Burp history JSON
├── references/
│   ├── auth_patterns.md             # Regex patterns and flow classification rules
│   ├── security_checklist.md        # Security evaluation criteria
│   └── example_output.md            # DVWA example for formatting reference
└── platforms/
    ├── claude/
    │   └── burp-authentication-mapper.zip   # Claude Code skill package
    └── gemini/
        └── GEMINI.md                        # Gemini CLI context file
```

`prompt.md` is the authoritative source. Platform files in `platforms/` are derived from it.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
