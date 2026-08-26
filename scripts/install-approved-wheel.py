#!/usr/bin/env python3
"""Install an approved ADAF-ATTACK wheel into a new virtual environment.

This is the portable bootstrap for internal release bundles. It deliberately
refuses to reuse an existing environment so that the artifact and dependency
set being tested are unambiguous.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import venv
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


def _verify_manifest(wheel: Path, manifest_path: Path) -> dict[str, object]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"release manifest cannot be read: {manifest_path}: {exc}") from exc
    if manifest.get("schema") != 1:
        raise SystemExit(f"unsupported release manifest schema in {manifest_path}")
    rows = manifest.get("artifacts")
    if not isinstance(rows, list):
        raise SystemExit(f"release manifest has no artifacts list: {manifest_path}")
    row = next(
        (item for item in rows if isinstance(item, dict) and item.get("filename") == wheel.name),
        None,
    )
    if not isinstance(row, dict) or not isinstance(row.get("sha256"), str):
        raise SystemExit(f"wheel is not listed in release manifest: {wheel.name}")
    actual = _sha256(wheel)
    if actual != row["sha256"]:
        raise SystemExit(
            f"release artifact checksum mismatch for {wheel.name}: expected {row['sha256']}, got {actual}"
        )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True, help="Approved .whl file")
    parser.add_argument("--venv", type=Path, default=Path(".venv"))
    parser.add_argument(
        "--extras", default="full", help="Optional dependency extra (default: full)"
    )
    parser.add_argument("--index-url", help="Approved internal Python package index")
    parser.add_argument("--find-links", type=Path, help="Offline wheelhouse directory")
    parser.add_argument(
        "--manifest",
        type=Path,
        help="Release manifest to verify before installation",
    )
    args = parser.parse_args()

    wheel = args.wheel.resolve()
    venv_root = args.venv.resolve()
    if not wheel.is_file() or wheel.suffix != ".whl":
        parser.error(f"approved wheel does not exist or is not a .whl file: {wheel}")
    if args.index_url and args.find_links:
        parser.error("use either --index-url or --find-links, not both")
    if args.manifest and not args.manifest.is_file():
        parser.error(f"release manifest does not exist: {args.manifest.resolve()}")
    if venv_root.exists():
        parser.error(f"refusing to reuse existing virtual environment: {venv_root}")

    manifest = _verify_manifest(wheel, args.manifest.resolve()) if args.manifest else None
    if manifest and manifest.get("project") != "adaf-attack":
        parser.error(f"release manifest is for {manifest.get('project')!r}, not 'adaf-attack'")
    if args.find_links and args.manifest:
        wheelhouse_rows = manifest.get("wheelhouse", []) if manifest else []
        for row in wheelhouse_rows:
            if not isinstance(row, dict) or not isinstance(row.get("filename"), str):
                parser.error("release manifest contains an invalid wheelhouse row")
            path = args.find_links.resolve() / row["filename"]
            if not path.is_file():
                parser.error(f"wheelhouse file listed by manifest is missing: {path}")
            if _sha256(path) != row.get("sha256"):
                parser.error(f"wheelhouse checksum mismatch: {path}")

    venv.EnvBuilder(with_pip=True).create(venv_root)
    python = venv_root / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    requirement = f"{wheel}[{args.extras}]" if args.extras else str(wheel)
    _run([str(python), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"])
    install = [str(python), "-m", "pip", "install", requirement]
    if args.index_url:
        install.extend(["--index-url", args.index_url])
    if args.find_links:
        install.extend(["--no-index", "--find-links", str(args.find_links.resolve())])
    _run(install)
    _run([str(python), "-m", "pip", "check"])
    _run([str(python), "-m", "adaf_attack.cli", "--version"])
    _run([str(python), "-m", "adaf_attack.cli", "--format", "json", "doctor", "--explain"])
    smoke_workspace = venv_root.parent / f"{venv_root.name}-quickstart"
    _run(
        [
            str(python),
            "-m",
            "adaf_attack.cli",
            "--format",
            "json",
            "quickstart",
            "--workspace",
            str(smoke_workspace),
        ]
    )
    _run([str(python), "-m", "adaf_attack.cli", "--format", "json", "list-capabilities"])
    _run([str(python), "-m", "adaf_attack.cli", "--format", "json", "paths"])
    activate = venv_root / ("Scripts/Activate.ps1" if sys.platform == "win32" else "bin/activate")
    print(f"Install complete. Activate: {activate}")
    print("Verify with: adaf-attack doctor --profile user-readiness")
    print("Then run:    adaf-attack guide")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
