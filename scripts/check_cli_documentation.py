#!/usr/bin/env python3
"""Check that the maintained CLI reference covers every registered command."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "docs" / "CLI_REFERENCE.md"
_ROW = re.compile(r"^\|\s*`(adaf-attack(?:\s+[a-z][a-z0-9-]*)+)`\s*\|", re.MULTILINE)


def registered_commands() -> set[str]:
    sys.path.insert(0, str(ROOT / "src"))
    from adaf_attack.cli import app

    def collect(typer_app: object, prefix: str = "") -> set[str]:
        names: set[str] = set()
        for command in typer_app.registered_commands:  # type: ignore[attr-defined]
            name = command.name or (
                command.callback.__name__.replace("_", "-") if command.callback else ""
            )
            if name:
                names.add(f"{prefix}{name}")
        for group in typer_app.registered_groups:  # type: ignore[attr-defined]
            if not group.name:
                continue
            group_name = f"{prefix}{group.name}"
            names.add(group_name)
            if group.typer_instance is not None:
                names.update(collect(group.typer_instance, f"{group_name} "))
        return names

    return collect(app)


def documented_commands() -> list[str]:
    text = REFERENCE.read_text(encoding="utf-8")
    return [entry.removeprefix("adaf-attack ") for entry in _ROW.findall(text)]


def validate() -> list[str]:
    documented = documented_commands()
    registered = registered_commands()
    errors: list[str] = []
    duplicates = sorted({name for name in documented if documented.count(name) > 1})
    if duplicates:
        errors.append(f"duplicate CLI reference rows: {', '.join(duplicates)}")
    missing = sorted(registered - set(documented))
    extra = sorted(set(documented) - registered)
    if missing:
        errors.append(f"registered commands missing from CLI reference: {', '.join(missing)}")
    if extra:
        errors.append(f"CLI reference contains unregistered commands: {', '.join(extra)}")
    return errors


def main() -> int:
    errors = validate()
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"CLI DOCUMENTATION PASSED: {REFERENCE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
