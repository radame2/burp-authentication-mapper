# Contributing to burp-authentication-mapper

Thanks for contributing. This document explains how the repo is structured and how to submit improvements.

## How It Works

`prompt.md` is the **canonical source of truth** for this workflow. It contains the full AI instructions in plain markdown and is platform-agnostic.

The platform files are thin wrappers derived from `prompt.md`:

| File | Purpose |
|---|---|
| `platforms/claude/burp-authentication-mapper.zip` | Claude Code skill package |
| `platforms/gemini/GEMINI.md` | Gemini CLI context file |

## What to Improve

| Area | File(s) | What good contributions look like |
|---|---|---|
| Workflow logic | `prompt.md` | Better step ordering, clearer instructions, new edge cases |
| Pattern detection | `references/auth_patterns.md` | New regex patterns, additional flow types, more classification rules |
| Security checks | `references/security_checklist.md` | New security findings, updated risk ratings, additional categories |
| Parser script | `scripts/parse_burp_history.py` | Bug fixes, new session ID formats, better classification logic |
| Example output | `references/example_output.md` | Additional real-world examples beyond DVWA |
| Platform support | `platforms/` | New platform adapters (e.g., Copilot, Cursor, Continue.dev) |

## Submitting a Pull Request

1. **Fork** the repo and create a branch from `main`
2. **Make your changes** — all prompt improvements go into `prompt.md`
3. **Sync platform files** if you changed `prompt.md`:
   - Copy updated content into `platforms/gemini/GEMINI.md`
   - Note in your PR description that the Claude skill zip needs rebuilding (a maintainer will handle this)
4. **Test your changes** locally before submitting:
   - For script changes: run `python3 scripts/parse_burp_history.py --help` and test against a real Burp history export
   - For prompt changes: test the updated workflow with your AI client against a known authentication flow
5. **Open a PR** with a clear description of what changed and why

## Adding a New Platform

If you want to add support for another AI platform (Copilot, Cursor, Continue.dev, etc.):

1. Create a new directory under `platforms/your-platform/`
2. Adapt `prompt.md` to that platform's format (system prompt, config file, extension manifest, etc.)
3. Document the setup steps in `README.md` under a new "Platform Setup" section
4. Open a PR — include a brief note on how you tested it

## Maintainer Responsibilities

The Claude skill `.zip` requires repacking after `prompt.md` changes. If you are a maintainer:

```bash
# From the repo root
cp prompt.md burp-authentication-mapper/SKILL.md   # restore front matter first — see note below
cp -r scripts references burp-authentication-mapper/
zip -r platforms/claude/burp-authentication-mapper.zip burp-authentication-mapper/
rm -rf burp-authentication-mapper/
```

> **Note:** The Claude skill `SKILL.md` requires a YAML front matter block at the top (name, description). When syncing from `prompt.md`, prepend the front matter before packing. See the existing `SKILL.md` inside the zip for the correct format.

## Code Style

- Python: follow PEP 8, keep functions focused and documented
- Markdown: use ATX headings (`#`), tables for structured data, fenced code blocks with language tags
- No trailing whitespace, Unix line endings
