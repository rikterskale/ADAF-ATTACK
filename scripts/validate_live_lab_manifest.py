#!/usr/bin/env python3
"""Validate a disposable AD lab manifest without contacting the lab."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path
from typing import Any

REQUIRED = {
    "schema_version",
    "domain",
    "domain_netbios",
    "dc_hostname",
    "dc_ip",
    "network_mode",
    "snapshot",
    "fixtures",
    "operator_account",
    "created_at",
    "expires_at",
}
FORBIDDEN = {"password", "passwd", "secret", "token", "private_key", "nt_hash", "lm_hash", "ccache"}


def _keys(value: Any) -> list[str]:
    if isinstance(value, dict):
        result: list[str] = []
        for key, child in value.items():
            if str(key).lower() in FORBIDDEN:
                result.append(str(key))
            result.extend(_keys(child))
        return result
    if isinstance(value, list):
        return [key for child in value for key in _keys(child)]
    return []


def validate_manifest(path: Path) -> list[str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"invalid lab manifest: {exc}"]
    if not isinstance(payload, dict):
        return ["lab manifest must be a JSON object"]
    errors = [f"lab manifest missing field: {key}" for key in sorted(REQUIRED - payload.keys())]
    if payload.get("schema_version") != 1:
        errors.append("lab manifest schema_version must be 1")
    if not isinstance(payload.get("domain"), str) or not payload.get("domain", "").lower().endswith(
        (".example", ".test", ".invalid")
    ):
        errors.append("domain must use a reserved lab suffix: .example, .test, or .invalid")
    try:
        address = ipaddress.ip_address(str(payload.get("dc_ip", "")))
        if not (address.is_private or address.is_loopback or address.is_reserved):
            errors.append("dc_ip must be private, loopback, or documentation-only")
    except ValueError:
        errors.append("dc_ip must be a valid IP address")
    if payload.get("network_mode") not in {"host-only", "internal"}:
        errors.append("network_mode must be host-only or internal")
    if not isinstance(payload.get("fixtures"), list) or not payload["fixtures"]:
        errors.append("fixtures must be a non-empty list")
    if _keys(payload):
        errors.append("lab manifest must not contain credentials or secret fields")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    errors = validate_manifest(args.manifest)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"LIVE LAB MANIFEST PASSED: {args.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
