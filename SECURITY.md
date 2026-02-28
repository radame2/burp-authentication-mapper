# Security Policy

## Scope

This policy applies to vulnerabilities in the **burp-authentication-mapper tool itself** — for example:

- A bug in `parse_burp_history.py` that leaks or mishandles captured proxy data
- A workflow instruction in `prompt.md` that could cause an AI client to take unintended actions
- A flaw in the sync script that reads or writes to unintended file paths

This is **not** the right place to report vulnerabilities discovered *using* this tool against target applications. Report those to the relevant application's security team.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report privately via GitHub's built-in mechanism:
1. Go to the [Security tab](https://github.com/radame2/burp-authentication-mapper/security)
2. Click **"Report a vulnerability"**
3. Provide a description, steps to reproduce, and impact assessment

You can expect an acknowledgement within **72 hours** and a resolution or status update within **14 days**.

## Responsible Use

This tool is intended for **authorized security testing, CTF competitions, and educational purposes only**. Only use it against systems you own or have explicit written permission to test. Misuse of this tool against systems without authorization may violate applicable laws.
