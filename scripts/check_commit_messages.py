#!/usr/bin/env python3
"""Checks commit subjects against the repo convention (AGENTS.md):

    <type>(<optional scope>)<optional !>: <gitmoji> <description>

Usage: check_commit_messages.py <git revision range>   e.g. origin/main..HEAD
"""
import re
import subprocess
import sys
import unicodedata

TYPES = "feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert"
HEADER = re.compile(rf"^(?:{TYPES})(?:\([a-z0-9._/-]+\))?!?: (?P<rest>.+)$")


def problem(subject: str) -> str | None:
    m = HEADER.match(subject)
    if not m:
        return f"must start with `<type>(<scope>): `, where type is one of {TYPES.replace('|', ', ')}"
    rest = m.group("rest")
    first = rest[0]
    if unicodedata.category(first) != "So":
        return "a gitmoji (https://gitmoji.dev, as a Unicode emoji) must follow the colon"
    description = rest[1:].lstrip("️").lstrip()
    if not description or rest[1:2] not in (" ", "️"):
        return "a description must follow the gitmoji, separated by a space"
    return None


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    log = subprocess.run(
        ["git", "log", "--no-merges", "--format=%H%x09%s", sys.argv[1]],
        check=True, capture_output=True, text=True,
    ).stdout
    failures = 0
    for line in filter(None, log.splitlines()):
        sha, subject = line.split("\t", 1)
        if (reason := problem(subject)) is not None:
            failures += 1
            print(f"{sha[:12]} {subject!r}\n    {reason}")
    if failures:
        print(f"\n{failures} commit message(s) don't follow the convention (see AGENTS.md).")
        return 1
    print("commit messages OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
