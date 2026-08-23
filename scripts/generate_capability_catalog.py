#!/usr/bin/env python3
"""Regenerate docs/CAPABILITY_CATALOG.md from the live capability registry.

CI runs this and asserts the working copy matches; a stale file fails CI.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

OUTPUT = ROOT / "docs" / "CAPABILITY_CATALOG.md"

HEADER = """# Capability catalog

This document is regenerated from the running package by
`scripts/generate_capability_catalog.py`. Do not edit by hand; run the
script (CI enforces parity).

| ID | Category | Maturity | Environment | Tools | Fixture | Difficulty | Risk | Approval | Rollback | Summary |
|----|----------|----------|-------------|-------|---------|------------|------|----------|----------|---------|
"""


def _rows() -> list[str]:
    import adaf_attack.capabilities  # noqa: F401  - registers capabilities
    from adaf_attack.core.registry import capability_registry

    lines: list[str] = []
    for cap_id in sorted(capability_registry.ids()):
        cap = capability_registry.get(cap_id)
        if cap is None:
            continue
        summary = (cap.summary or "").replace("|", "\\|")
        safety = getattr(cap, "safety", None)
        risk = (
            safety.risk.value
            if safety is not None
            else ("destructive" if cap.destructive else "observe")
        )
        approval = (
            safety.approval.value
            if safety is not None
            else ("force_and_ack" if cap.destructive else "none")
        )
        rollback = safety.rollback.value if safety is not None else "unknown"
        difficulty = getattr(cap, "difficulty", "-") or "-"
        category = getattr(cap, "category", "-") or "-"
        maturity = getattr(cap, "maturity", "implemented") or "implemented"
        environment = getattr(cap, "environment", "unknown") or "unknown"
        tools = ", ".join(getattr(cap, "tools", ()) or ()) or "-"
        fixture = getattr(cap, "fixture", None) or "-"
        lines.append(
            f"| `{cap.id}` | {category} | {maturity} | {environment} | {tools} | "
            f"{fixture} | {difficulty} | {risk} | {approval} | {rollback} | {summary} |"
        )
    return lines


def render() -> str:
    return HEADER + "\n".join(_rows()) + "\n"


def main() -> int:
    check = "--check" in sys.argv
    content = render()
    if check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != content:
            print(
                "docs/CAPABILITY_CATALOG.md is stale. Run:\n"
                "  python scripts/generate_capability_catalog.py",
                file=sys.stderr,
            )
            return 1
        print("capability catalog is current.")
        return 0
    OUTPUT.write_text(content, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
