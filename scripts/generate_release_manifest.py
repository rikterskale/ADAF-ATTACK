#!/usr/bin/env python3
"""Generate and validate the machine-readable release bundle manifest.

The manifest is dependency-free so it can be used before the operator
environment is installed. It describes exact distribution and wheelhouse files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

ARTIFACT_SUFFIXES = (".whl", ".tar.gz")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _project_metadata(repo_root: Path) -> dict[str, Any]:
    data = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    project = data.get("project")
    if not isinstance(project, dict):
        raise ValueError("pyproject.toml does not contain [project]")
    return project


def _artifact_rows(directory: Path) -> list[dict[str, str]]:
    artifacts = sorted(
        path for path in directory.iterdir() if path.is_file() and path.name.endswith(ARTIFACT_SUFFIXES)
    )
    if not artifacts:
        raise ValueError(f"no wheel or sdist artifacts found in {directory}")
    return [{"filename": path.name, "sha256": _sha256(path)} for path in artifacts]


def _wheelhouse_rows(directory: Path | None) -> list[dict[str, str]]:
    if directory is None:
        return []
    if not directory.is_dir():
        raise ValueError(f"wheelhouse does not exist or is not a directory: {directory}")
    return [
        {"filename": path.name, "sha256": _sha256(path)}
        for path in sorted(directory.iterdir())
        if path.is_file() and path.name not in {"SHA256SUMS", "release-manifest.json"}
    ]


def build_manifest(repo_root: Path, dist: Path, wheelhouse: Path | None) -> dict[str, Any]:
    project = _project_metadata(repo_root)
    extras = project.get("optional-dependencies", {})
    return {
        "schema": 1,
        "project": project["name"],
        "version": project["version"],
        "requires_python": project["requires-python"],
        "artifacts": _artifact_rows(dist),
        "extras": {name: list(values) for name, values in sorted(extras.items())},
        "wheelhouse": _wheelhouse_rows(wheelhouse),
    }


def validate_manifest(
    manifest: dict[str, Any], *, dist: Path | None = None, wheelhouse: Path | None = None
) -> None:
    required = {"schema", "project", "version", "requires_python", "artifacts", "extras", "wheelhouse"}
    missing = required - manifest.keys()
    if missing:
        raise ValueError(f"manifest is missing keys: {sorted(missing)}")
    if manifest["schema"] != 1:
        raise ValueError(f"unsupported manifest schema: {manifest['schema']!r}")
    if not manifest["artifacts"]:
        raise ValueError("manifest contains no distribution artifacts")
    for row in [*manifest["artifacts"], *manifest["wheelhouse"]]:
        if not isinstance(row, dict) or not isinstance(row.get("filename"), str):
            raise ValueError(f"invalid manifest file row: {row!r}")
        if not isinstance(row.get("sha256"), str) or not SHA256_RE.fullmatch(row["sha256"]):
            raise ValueError(f"invalid SHA256 for {row.get('filename')!r}")

    if dist is not None:
        for row in manifest["artifacts"]:
            path = dist / row["filename"]
            if not path.is_file():
                raise ValueError(f"manifest artifact is missing: {path}")
            if _sha256(path) != row["sha256"]:
                raise ValueError(f"manifest artifact checksum mismatch: {path}")

    if wheelhouse is not None:
        for row in manifest["wheelhouse"]:
            path = wheelhouse / row["filename"]
            if not path.is_file():
                raise ValueError(f"manifest wheelhouse file is missing: {path}")
            if _sha256(path) != row["sha256"]:
                raise ValueError(f"manifest wheelhouse checksum mismatch: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--validate", action="store_true", help="validate an existing output manifest")
    args = parser.parse_args()

    try:
        if args.validate:
            manifest = json.loads(args.output.read_text(encoding="utf-8"))
        else:
            manifest = build_manifest(args.repo_root.resolve(), args.dist.resolve(), args.wheelhouse)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        validate_manifest(manifest, dist=args.dist.resolve(), wheelhouse=args.wheelhouse)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"release manifest validation failed: {exc}", file=sys.stderr)
        return 1

    print(f"release manifest valid: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
