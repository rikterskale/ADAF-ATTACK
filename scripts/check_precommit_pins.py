#!/usr/bin/env python3
"""Fail when pre-commit hook versions drift from the CI lockfile.

Compares the ruff `rev:` in `.pre-commit-config.yaml` against the pinned
`ruff==` line in `requirements-ci.txt`. If they disagree, contributor and CI
formatters will disagree - which is the actual failure mode we protect against.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _ci_version(package: str) -> str:
    text = (ROOT / "requirements-ci.txt").read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(package)}==([^\s\\]+)", text, flags=re.MULTILINE)
    if match is None:
        raise SystemExit(f"{package}: not pinned in requirements-ci.txt")
    return match.group(1)


def _precommit_rev(repo_fragment: str) -> str:
    text = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    pattern = re.compile(
        rf"repo: [^\n]*{re.escape(repo_fragment)}[^\n]*\n\s*(?:#[^\n]*\n\s*)*rev:\s*([^\s]+)",
        re.MULTILINE,
    )
    match = pattern.search(text)
    if match is None:
        raise SystemExit(f"pre-commit repo missing: {repo_fragment}")
    return match.group(1)


def main() -> int:
    checks = [("ruff", "astral-sh/ruff-pre-commit", "v")]
    failures: list[str] = []
    for pkg, repo, prefix in checks:
        ci = _ci_version(pkg)
        rev = _precommit_rev(repo).lstrip(prefix)
        if ci != rev:
            failures.append(f"{pkg}: pre-commit rev={rev!r} != CI pin={ci!r}")

    if failures:
        for line in failures:
            print(f"FAIL: {line}", file=sys.stderr)
        print(
            "\nUpdate `.pre-commit-config.yaml` rev fields to match requirements-ci.txt.",
            file=sys.stderr,
        )
        return 1
    print("pre-commit hooks match CI-pinned versions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
