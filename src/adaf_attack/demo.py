"""Packaged, deterministic offline demo session helpers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

_DEMO_FILES = ("acl-enum.json", "adcs-enum.json")


def materialize_demo_session(destination: Path) -> Path:
    """Create a demo session from package data without requiring a checkout."""
    destination.mkdir(parents=True, exist_ok=True)
    source = files("adaf_attack.demo_data")
    for filename in _DEMO_FILES:
        resource = source.joinpath(filename)
        if not resource.is_file():
            raise FileNotFoundError(f"Packaged demo fixture is missing: {filename}")
        (destination / filename).write_bytes(resource.read_bytes())
    (destination / "session.json").write_text(
        json.dumps(
            {
                "session_id": "demo-session",
                "created_at": datetime.now(UTC).isoformat(),
                "demo": True,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return destination
