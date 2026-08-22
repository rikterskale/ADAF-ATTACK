#!/usr/bin/env python3
"""Generate and validate an offline release provenance statement.

The statement binds the release artifacts to the source revision and build
context.  A publisher may additionally set ``ADAF_RELEASE_PROVENANCE_KEY`` to
emit an HMAC signature; without that key the file is an integrity manifest,
not an authenticity claim.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _git_revision(repo_root: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"], text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return os.environ.get("GITHUB_SHA", "unknown")


def _unsigned_payload(document: dict[str, Any]) -> bytes:
    payload = {key: value for key, value in document.items() if key != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_provenance(repo_root: Path, dist: Path) -> dict[str, Any]:
    artifacts = sorted(path for path in dist.iterdir() if path.is_file())
    if not artifacts:
        raise ValueError(f"no release files found in {dist}")
    document: dict[str, Any] = {
        "schema": 1,
        "project": "adaf-attack",
        "source_revision": _git_revision(repo_root),
        "source_date_epoch": os.environ.get("SOURCE_DATE_EPOCH"),
        "workflow": os.environ.get("GITHUB_WORKFLOW"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "artifacts": [{"filename": path.name, "sha256": _sha256(path)} for path in artifacts],
    }
    key = os.environ.get("ADAF_RELEASE_PROVENANCE_KEY")
    if key:
        signature = hmac.new(key.encode("utf-8"), _unsigned_payload(document), hashlib.sha256)
        document["signature"] = {
            "algorithm": "HMAC-SHA256",
            "key_id": os.environ.get("ADAF_RELEASE_PROVENANCE_KEY_ID", "default"),
            "value": signature.hexdigest(),
        }
    else:
        document["signature"] = None
    return document


def validate_provenance(document: dict[str, Any], *, dist: Path | None = None) -> None:
    if document.get("schema") != 1:
        raise ValueError(f"unsupported provenance schema: {document.get('schema')!r}")
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("provenance contains no artifacts")
    for row in artifacts:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("filename"), str)
            or not isinstance(row.get("sha256"), str)
            or len(row["sha256"]) != 64
        ):
            raise ValueError(f"invalid provenance artifact row: {row!r}")
        if dist is not None:
            path = dist / row["filename"]
            if not path.is_file() or _sha256(path) != row["sha256"]:
                raise ValueError(f"provenance checksum mismatch: {path}")
    signature = document.get("signature")
    if signature is not None:
        if not isinstance(signature, dict) or signature.get("algorithm") != "HMAC-SHA256":
            raise ValueError("unsupported provenance signature")
        key = os.environ.get("ADAF_RELEASE_PROVENANCE_KEY")
        if key:
            expected = hmac.new(key.encode("utf-8"), _unsigned_payload(document), hashlib.sha256)
            if not hmac.compare_digest(str(signature.get("value")), expected.hexdigest()):
                raise ValueError("provenance signature mismatch")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    try:
        if args.validate:
            document = json.loads(args.output.read_text(encoding="utf-8"))
        else:
            document = build_provenance(args.repo_root.resolve(), args.dist.resolve())
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        if not isinstance(document, dict):
            raise ValueError("provenance must be a JSON object")
        validate_provenance(document, dist=args.dist.resolve())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"release provenance validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"release provenance valid: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
