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

---

## Platform Setup

### Claude Code

Install the skill:

```bash
cp platforms/claude/burp-authentication-mapper.zip ~/.claude/skills/
```

Restart Claude Code. Invoke with:

```
/burp-authentication-mapper
/burp-authentication-mapper 30m
/burp-authentication-mapper 1h
```

---

### Gemini CLI

Three integration options are available, from simplest to most explicit.

#### Option A — gemini-cli-skillz (recommended)

[gemini-cli-skillz](https://github.com/intellectronica/gemini-cli-skillz) is a Gemini CLI extension that loads Claude Code `SKILL.md` skills directly, letting you share one skills directory across both AI clients.

**1. Install the extension:**

```bash
gemini extensions install https://github.com/intellectronica/gemini-cli-skillz
```

**2. Symlink your Claude Code skills directory:**

```bash
ln -s ~/.claude/skills ~/.skillz
```

Or if you are not using Claude Code, copy the skill directly:

```bash
mkdir -p ~/.skillz
cp platforms/claude/burp-authentication-mapper.zip ~/.skillz/
```

**3. Restart Gemini CLI.** Invoke via natural language:

```
Map the authentication flow I just captured in Burp
```

#### Option B — Native Gemini CLI Skills

Gemini CLI's built-in Agent Skills system reads skill directories from `~/.gemini/skills/`.

**1. Extract and copy the skill:**

```bash
mkdir -p ~/.gemini/skills
cd /tmp && unzip ~/path/to/platforms/claude/burp-authentication-mapper.zip
cp -r burp-authentication-mapper ~/.gemini/skills/
```

**2. Restart Gemini CLI.** Invoke via natural language:

```
Map the authentication flow I just captured in Burp
```

#### Option C — Custom Slash Command

For an explicit `/burp-auth-map` slash command in Gemini CLI, copy the provided TOML file:

```bash
mkdir -p ~/.gemini/commands
cp platforms/gemini/burp-auth-map.toml ~/.gemini/commands/
```

Reload commands without restarting:

```
/commands reload
```

Invoke with:

```
/burp-auth-map
```

> **Note:** Option C works best when paired with Option A or B so Gemini has access to the full skill instructions, reference files, and parser script.

#### Manual Context (fallback)

If you prefer not to install a skill, copy `platforms/gemini/GEMINI.md` into your working directory before starting a Gemini CLI session:

```bash
cp platforms/gemini/GEMINI.md .
gemini
```

Gemini will load the workflow instructions automatically from the current directory.

---

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
├── platforms/
│   ├── claude/
│   │   └── burp-authentication-mapper.zip   # Claude Code skill package
│   └── gemini/
│       ├── GEMINI.md                        # Standalone context file (manual fallback)
│       └── burp-auth-map.toml               # Gemini CLI slash command definition
└── tools/
    └── burp-authentication-mapper-sync/     # Companion skill to sync edits back to this repo
```

`prompt.md` is the authoritative source. Platform files in `platforms/` are derived from it.

## Legal & Responsible Use

This tool is intended for **authorized security testing, CTF competitions, and educational purposes only**. Only use it against systems you own or have explicit written permission to test.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
