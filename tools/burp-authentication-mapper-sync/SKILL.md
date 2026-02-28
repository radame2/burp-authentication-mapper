---
name: burp-authentication-mapper-sync
description: "Syncs the burp-authentication-mapper skill from ~/.claude/skills/burp-authentication-mapper.zip to the GitHub repo at ~/Documents/ClaudeCode/burp-authentication-mapper/. Run this after making native edits to the skill in Claude Code. Strips YAML front matter from SKILL.md to produce prompt.md and platforms/gemini/GEMINI.md, copies scripts/ and references/, and updates platforms/claude/ with the latest zip. Shows a summary of changes and offers to commit."
---

# Burp Authentication Mapper Sync

Sync the installed burp-authentication-mapper skill to its GitHub repo after native edits.

## Workflow

### Step 1: Run the Sync Script

Run the sync script to unpack the skill zip and propagate changes to the repo:

```bash
python3 scripts/sync.py
```

The script outputs a list of updated, created, or unchanged files. Exit code 0 means no changes; non-zero means changes were made.

### Step 2: Show Changes

Run a git diff to show exactly what changed in the repo:

```bash
git -C ~/Documents/ClaudeCode/burp-authentication-mapper diff
```

Present the diff to the user as a readable summary — highlight which sections of `prompt.md` changed (workflow steps, edge cases, resources, etc.) rather than showing raw diff output.

### Step 3: Offer to Commit

If there are changes, ask the user whether they want to commit. If yes:

1. Stage all changed files:

```bash
git -C ~/Documents/ClaudeCode/burp-authentication-mapper add -A
```

2. Ask the user to confirm or provide a commit message. Suggest a default:

```
update burp-authentication-mapper: <brief description of what changed>
```

3. Commit with the confirmed message.

## Edge Cases

- **No changes detected:** Report that the repo is already up to date. No further action needed.
- **Skill zip not found:** Report that `~/.claude/skills/burp-authentication-mapper.zip` is missing and ask the user to verify the skill is installed.
- **Repo directory not found:** Report that `~/Documents/ClaudeCode/burp-authentication-mapper/` does not exist.
- **Git not initialized:** If the repo has not been set up with git yet, skip Steps 2 and 3 and inform the user.
