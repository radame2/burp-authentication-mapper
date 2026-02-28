#!/usr/bin/env python3
"""
Sync burp-authentication-mapper skill from ~/.claude/skills/ to the GitHub repo.

Unpacks the skill zip, strips YAML front matter from SKILL.md to produce
prompt.md and platforms/gemini/GEMINI.md, copies scripts/ and references/,
and updates platforms/claude/ with the latest zip.

Usage:
    python3 sync.py [--skill-zip PATH] [--repo-dir PATH]

Exit codes:
    0 — no changes (repo already up to date)
    1 — changes were made
    2 — error
"""

import argparse
import shutil
import sys
import zipfile
from pathlib import Path

SKILL_ZIP_DEFAULT = Path.home() / ".claude" / "skills" / "burp-authentication-mapper.zip"
REPO_DIR_DEFAULT = Path.home() / "Documents" / "ClaudeCode" / "burp-authentication-mapper"


def strip_front_matter(content: str) -> str:
    """Strip YAML front matter (--- ... ---) from the top of a markdown string."""
    lines = content.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return content
    for i, line in enumerate(lines[1:], 1):
        if line.strip() == "---":
            return "".join(lines[i + 1:]).lstrip("\n")
    return content


def sync_text_file(src: Path, dst: Path, transform=None) -> str:
    """Write src content to dst, optionally transforming it. Returns change status."""
    content = src.read_text()
    if transform:
        content = transform(content)
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() and dst.read_text() == content:
        return "unchanged"
    dst.write_text(content)
    return "updated" if dst.exists() else "created"


def sync_binary_file(src: Path, dst: Path) -> str:
    """Copy binary file from src to dst. Returns change status."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    data = src.read_bytes()
    if dst.exists() and dst.read_bytes() == data:
        return "unchanged"
    dst.write_bytes(data)
    return "updated" if dst.exists() else "created"


def sync_directory(src_dir: Path, dst_dir: Path) -> dict:
    """Sync all files from src_dir to dst_dir. Returns {relative_path: status}."""
    results = {}
    dst_dir.mkdir(parents=True, exist_ok=True)
    for src_file in sorted(src_dir.iterdir()):
        if src_file.is_file():
            dst_file = dst_dir / src_file.name
            data = src_file.read_bytes()
            if dst_file.exists() and dst_file.read_bytes() == data:
                results[src_file.name] = "unchanged"
            else:
                was_existing = dst_file.exists()
                dst_file.write_bytes(data)
                results[src_file.name] = "updated" if was_existing else "created"
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Sync burp-authentication-mapper skill to its GitHub repo"
    )
    parser.add_argument(
        "--skill-zip", type=Path, default=SKILL_ZIP_DEFAULT,
        help=f"Path to installed skill zip (default: {SKILL_ZIP_DEFAULT})"
    )
    parser.add_argument(
        "--repo-dir", type=Path, default=REPO_DIR_DEFAULT,
        help=f"Path to GitHub repo (default: {REPO_DIR_DEFAULT})"
    )
    args = parser.parse_args()

    skill_zip = args.skill_zip.expanduser().resolve()
    repo_dir = args.repo_dir.expanduser().resolve()

    # Validate inputs
    if not skill_zip.exists():
        print(f"ERROR: Skill zip not found: {skill_zip}", file=sys.stderr)
        print("Verify the skill is installed in Claude Code.", file=sys.stderr)
        return 2

    if not repo_dir.exists():
        print(f"ERROR: Repo directory not found: {repo_dir}", file=sys.stderr)
        return 2

    print(f"Skill zip : {skill_zip}")
    print(f"Repo dir  : {repo_dir}")
    print()

    # Extract zip to temp dir
    tmp_dir = Path("/tmp/burp-auth-mapper-sync")
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir()

    with zipfile.ZipFile(skill_zip, "r") as zf:
        zf.extractall(tmp_dir)

    # Find skill root — may be nested one level inside a subdirectory
    extracted = list(tmp_dir.iterdir())
    skill_root = extracted[0] if len(extracted) == 1 and extracted[0].is_dir() else tmp_dir

    results = {}

    # 1. SKILL.md → prompt.md (strip front matter)
    skill_md = skill_root / "SKILL.md"
    if skill_md.exists():
        results["prompt.md"] = sync_text_file(
            skill_md, repo_dir / "prompt.md", transform=strip_front_matter
        )
        # 2. SKILL.md → platforms/gemini/GEMINI.md (strip front matter)
        results["platforms/gemini/GEMINI.md"] = sync_text_file(
            skill_md, repo_dir / "platforms" / "gemini" / "GEMINI.md", transform=strip_front_matter
        )
    else:
        print("WARNING: SKILL.md not found in zip — skipping prompt.md and GEMINI.md", file=sys.stderr)

    # 3. scripts/ → scripts/
    src_scripts = skill_root / "scripts"
    if src_scripts.exists():
        for name, status in sync_directory(src_scripts, repo_dir / "scripts").items():
            results[f"scripts/{name}"] = status

    # 4. references/ → references/
    src_refs = skill_root / "references"
    if src_refs.exists():
        for name, status in sync_directory(src_refs, repo_dir / "references").items():
            results[f"references/{name}"] = status

    # 5. Zip → platforms/claude/
    dst_zip = repo_dir / "platforms" / "claude" / skill_zip.name
    results[f"platforms/claude/{skill_zip.name}"] = sync_binary_file(skill_zip, dst_zip)

    # Cleanup
    shutil.rmtree(tmp_dir)

    # Report
    changed = {f: s for f, s in results.items() if s != "unchanged"}
    unchanged = {f: s for f, s in results.items() if s == "unchanged"}

    if changed:
        print("Changes:")
        for f, s in sorted(changed.items()):
            print(f"  {s:<10}  {f}")
        print()

    if unchanged:
        print(f"Unchanged: {len(unchanged)} file(s) — " + ", ".join(sorted(unchanged)))
        print()

    if not changed:
        print("Repo is already up to date.")
        return 0

    print("Sync complete.")
    return 1  # non-zero signals changes were made (useful for git status checks)


if __name__ == "__main__":
    sys.exit(main())
