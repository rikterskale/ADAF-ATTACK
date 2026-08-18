#!/usr/bin/env python3
"""Build a hash-recorded release wheelhouse for an approved artifact."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path


def _run(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True, help="Approved wheel or sdist")
    parser.add_argument("--output", type=Path, default=Path("wheelhouse"))
    parser.add_argument("--extras", default="full")
    parser.add_argument("--index-url")
    args = parser.parse_args()

    artifact = args.wheel.resolve()
    output = args.output.resolve()
    if not artifact.is_file() or not artifact.name.endswith((".whl", ".tar.gz")):
        parser.error(f"approved artifact does not exist or is unsupported: {artifact}")
    if output.exists() and any(output.iterdir()):
        parser.error(f"refusing to reuse a non-empty wheelhouse: {output}")
    output.mkdir(parents=True, exist_ok=True)

    requirement = f"{artifact}[{args.extras}]" if args.extras else str(artifact)
    command = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--only-binary=:all:",
        "--dest",
        str(output),
        requirement,
    ]
    if args.index_url:
        command.extend(["--index-url", args.index_url])
    _run(command)

    checksum_file = output / "SHA256SUMS"
    rows = [
        f"{_sha256(path)}  {path.name}"
        for path in sorted(output.iterdir())
        if path.is_file()
    ]
    checksum_file.write_text("\n".join(rows) + "\n", encoding="utf-8")
    _run(
        [
            sys.executable,
            "scripts/generate_release_manifest.py",
            "--repo-root",
            ".",
            "--dist",
            str(artifact.parent),
            "--wheelhouse",
            str(output),
            "--output",
            str(output / "release-manifest.json"),
        ]
    )
    print(f"wheelhouse ready: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
