#!/usr/bin/env python3
"""Validate that every registered capability has a live-readiness classification."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MATRIX = ROOT / "docs" / "LIVE_CAPABILITY_MATRIX.json"
ENVIRONMENTS = {"live-read-only", "live-mutating", "offline-analysis"}
STATUSES = {"supported", "experimental", "manual-only"}
REQUIRED_FIELDS = {"environment", "status", "network_required", "external_tools", "fixtures", "rollback", "evidence"}


def _registered() -> dict[str, Any]:
    sys.path.insert(0, str(ROOT / "src"))
    import adaf_attack.capabilities  # noqa: F401
    from adaf_attack.core.registry import capability_registry

    return {item.id: item for item in capability_registry.list()}


def validate_matrix(path: Path = DEFAULT_MATRIX) -> list[str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"invalid capability matrix: {exc}"]
    if not isinstance(payload, dict):
        return ["capability matrix must be a JSON object"]
    errors: list[str] = []
    if payload.get("schema_version") != 1:
        errors.append("capability matrix schema_version must be 1")
    capabilities = payload.get("capabilities")
    if not isinstance(capabilities, dict):
        return errors + ["capability matrix capabilities must be an object"]
    registered = _registered()
    missing = sorted(set(registered) - set(capabilities))
    extra = sorted(set(capabilities) - set(registered))
    if missing:
        errors.append(f"capability matrix is missing registered capabilities: {', '.join(missing)}")
    if extra:
        errors.append(f"capability matrix contains unknown capabilities: {', '.join(extra)}")
    for capability_id, item in capabilities.items():
        if not isinstance(item, dict):
            errors.append(f"{capability_id}: classification must be an object")
            continue
        missing_fields = sorted(REQUIRED_FIELDS - item.keys())
        if missing_fields:
            errors.append(f"{capability_id}: missing fields: {', '.join(missing_fields)}")
            continue
        if item["environment"] not in ENVIRONMENTS:
            errors.append(f"{capability_id}: invalid environment")
        if item["status"] not in STATUSES:
            errors.append(f"{capability_id}: invalid status")
        if not isinstance(item["network_required"], bool):
            errors.append(f"{capability_id}: network_required must be boolean")
        for field in ("external_tools", "fixtures", "evidence"):
            if not isinstance(item[field], list) or not all(isinstance(value, str) and value for value in item[field]):
                errors.append(f"{capability_id}: {field} must be a non-empty-text list")
        if not isinstance(item["rollback"], str) or not item["rollback"]:
            errors.append(f"{capability_id}: rollback must be non-empty text")
        if capability_id in registered and registered[capability_id].destructive and item["rollback"] != "required":
            errors.append(f"{capability_id}: destructive capability must declare rollback=required")
        if item["environment"].startswith("live-") and item["network_required"] is not True:
            errors.append(f"{capability_id}: live capability must set network_required=true")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    args = parser.parse_args()
    errors = validate_matrix(args.matrix)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"LIVE CAPABILITY MATRIX PASSED: {args.matrix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
