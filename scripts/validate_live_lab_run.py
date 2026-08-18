#!/usr/bin/env python3
"""Validate a sanitized evidence bundle from the disposable AD lab.

This tool is deliberately offline. It checks that the live-lab run produced
the minimum evidence needed for release sign-off and that obvious secret
material was not copied into the bundle.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "private_key",
    "privatekey",
    "nt_hash",
    "lm_hash",
    "ccache",
}
REDACTED = {"", "[redacted]", "<redacted>", "redacted", "none", "null"}
RECORD_REQUIRED = {
    "schema_version",
    "release_version",
    "commit_sha",
    "lab_snapshot",
    "operator_os",
    "operator_python",
    "read_only_smoke",
    "optional_capabilities",
    "force_guard",
    "mutation_rollback",
    "evidence_validator",
    "sanitized_evidence_location",
    "reviewer",
    "review_date",
}
PASS_STATUSES = {"pass", "fail", "not_run"}


def _walk_sensitive(value: Any, path: str = "$") -> list[str]:
    problems: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if str(key).lower() in SENSITIVE_KEYS and str(child).strip().lower() not in REDACTED:
                problems.append(child_path)
            problems.extend(_walk_sensitive(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            problems.extend(_walk_sensitive(child, f"{path}[{index}]"))
    return problems


def validate_bundle(root: Path, required: list[str]) -> list[str]:
    errors: list[str] = []
    if not root.is_dir():
        return [f"evidence directory does not exist: {root}"]
    for relative in required:
        path = root / relative
        if not path.is_file():
            errors.append(f"required evidence file is missing: {relative}")
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"invalid JSON in {relative}: {exc}")
            continue
        for location in _walk_sensitive(payload):
            errors.append(f"possible unredacted secret field in {relative}: {location}")
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".key", ".pem", ".pfx", ".p12", ".ccache"}:
            errors.append(
                f"private or credential artifact must not be packaged: {path.relative_to(root)}"
            )
        if path.is_file() and re.search(
            r"password\s*[:=]\s*[^<\[]", path.read_text(encoding="utf-8", errors="ignore"), re.I
        ):
            errors.append(f"possible plaintext password in: {path.relative_to(root)}")
    return errors


def validate_release_record(path: Path) -> list[str]:
    """Validate the machine-readable release sign-off record."""
    if not path.is_file():
        return [f"release evidence record does not exist: {path}"]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"invalid release evidence record: {exc}"]
    if not isinstance(payload, dict):
        return ["release evidence record must be a JSON object"]
    errors = [f"release evidence record missing field: {key}" for key in sorted(RECORD_REQUIRED - payload.keys())]
    if payload.get("schema_version") != 1:
        errors.append("release evidence record schema_version must be 1")
    for key in ("release_version", "commit_sha", "lab_snapshot", "operator_os", "operator_python", "reviewer", "review_date"):
        if not isinstance(payload.get(key), str) or not payload[key].strip():
            errors.append(f"release evidence record field must be non-empty text: {key}")
    for key in ("read_only_smoke", "force_guard", "mutation_rollback", "evidence_validator"):
        if payload.get(key) not in PASS_STATUSES:
            errors.append(f"release evidence record status must be pass, fail, or not_run: {key}")
    capabilities = payload.get("optional_capabilities")
    if not isinstance(capabilities, list):
        errors.append("release evidence record optional_capabilities must be a list")
    else:
        for index, item in enumerate(capabilities):
            if not isinstance(item, dict) or not item.get("name") or item.get("status") not in PASS_STATUSES:
                errors.append(f"release evidence record optional_capabilities[{index}] is invalid")
    for location in _walk_sensitive(payload):
        errors.append(f"possible unredacted secret field in release record: {location}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--require", action="append", dest="required", default=[])
    parser.add_argument("--release-record", type=Path, help="Machine-readable release sign-off JSON")
    args = parser.parse_args()
    required = args.required or ["findings.json", "reports/report-manifest.json"]
    errors = validate_bundle(args.evidence_dir, required)
    if args.release_record:
        errors.extend(validate_release_record(args.release_record))
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"LIVE LAB EVIDENCE PASSED: {args.evidence_dir}")
    print(f"Validated files: {', '.join(required)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
