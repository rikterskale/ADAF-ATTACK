#!/usr/bin/env python3
"""Fail-closed SHA-256 verification for release wheels/sdists."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_digest(artifact: Path, *, manifest: Path | None, sha256: str | None) -> str:
    if sha256:
        return sha256.strip().lower()
    if manifest is not None:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        files = payload.get("files") or payload.get("artifacts") or []
        name = artifact.name
        for row in files:
            if not isinstance(row, dict):
                continue
            if row.get("filename") == name or row.get("name") == name:
                digest = str(row.get("sha256") or "")
                if digest:
                    return digest.lower()
        raise SystemExit(f"ERROR: {name} is not listed in {manifest}")
    sums = artifact.parent / "SHA256SUMS"
    if not sums.is_file():
        raise SystemExit(
            "ERROR: refusing to install a package without SHA256SUMS, --manifest, or --sha256. "
            "Place SHA256SUMS next to the wheel or pass a release-manifest.json."
        )
    needle = artifact.name
    for line in sums.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        digest, name = parts[0], parts[-1].lstrip("*")
        if Path(name).name == needle:
            return digest.lower()
    raise SystemExit(f"ERROR: {needle} is not listed in {sums}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--sha256")
    args = parser.parse_args()
    artifact = args.artifact.expanduser().resolve()
    if not artifact.is_file():
        print(f"ERROR: artifact not found: {artifact}", file=sys.stderr)
        return 1
    expected = expected_digest(artifact, manifest=args.manifest, sha256=args.sha256)
    actual = sha256_file(artifact)
    if actual != expected:
        print(
            f"ERROR: digest mismatch for {artifact.name}: expected {expected}, got {actual}",
            file=sys.stderr,
        )
        return 1
    print(f"OK {artifact.name} sha256={actual}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
