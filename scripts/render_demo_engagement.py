"""Build a polished offline report bundle from deterministic demo evidence."""

from __future__ import annotations

import shutil
from pathlib import Path

from adaf_attack.core.reporting import generate_report_bundle


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests" / "fixtures" / "demo-session"
OUTPUT = ROOT / "output" / "demo-engagement"


def main() -> None:
    if OUTPUT.exists():
        shutil.rmtree(OUTPUT)
    shutil.copytree(SOURCE, OUTPUT)
    result = generate_report_bundle(OUTPUT, engagement_id="DEMO-2026-001")
    print(result)


if __name__ == "__main__":
    main()
