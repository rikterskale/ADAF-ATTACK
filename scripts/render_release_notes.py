#!/usr/bin/env python3
"""Render release notes from the CHANGELOG's `## Unreleased` section.

Reads `CHANGELOG.md`, extracts everything between `## Unreleased` and the next
`## <version>` heading, and either prints the section (default) or writes it to
a file (with `--output`). During the release cut, invoke it twice: once with
`--output RELEASE.md` to refresh the shipped release notes, and once with
`--output /tmp/gh-release-body.md` to feed the GitHub release body.

Usage:
    python scripts/render_release_notes.py                  # print to stdout
    python scripts/render_release_notes.py --output RELEASE.md
    python scripts/render_release_notes.py --version 0.10.1 # rename ## Unreleased
    python scripts/render_release_notes.py --check          # non-zero if section is empty

Exit codes:
    0 - section rendered successfully.
    2 - CHANGELOG is missing the `## Unreleased` header.
    3 - `--check` was passed and the section body is empty.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"


def extract_unreleased(text: str) -> str:
    """Return the body of `## Unreleased`, without its heading."""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip().lower() == "## unreleased":
            start = i + 1
            break
    if start is None:
        raise SystemExit(2)
    end = len(lines)
    for j in range(start, len(lines)):
        if re.match(r"^## \S", lines[j]):
            end = j
            break
    return "\n".join(lines[start:end]).strip("\n")


def rename_heading(body: str, version: str) -> str:
    """Prepend a versioned heading to the extracted body."""
    return f"# ADAF-ATTACK {version} release notes\n\n{body}\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--changelog", type=Path, default=CHANGELOG)
    parser.add_argument("--output", type=Path, help="Write to this file instead of stdout.")
    parser.add_argument("--version", help="Render a `# ADAF-ATTACK <version> release notes` heading.")
    parser.add_argument("--check", action="store_true", help="Exit non-zero if body is empty.")
    args = parser.parse_args()

    text = args.changelog.read_text(encoding="utf-8")
    body = extract_unreleased(text)

    if args.check and not body.strip():
        print("No content in `## Unreleased` — nothing to release.", file=sys.stderr)
        return 3

    rendered = rename_heading(body, args.version) if args.version else body + "\n"

    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
