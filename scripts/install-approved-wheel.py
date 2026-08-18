#!/usr/bin/env python3
"""Install an approved ADAF-ATTACK wheel into a new virtual environment.

This is the portable bootstrap for internal release bundles. It deliberately
refuses to reuse an existing environment so that the artifact and dependency
set being tested are unambiguous.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import venv
from pathlib import Path


def _run(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True, help="Approved .whl file")
    parser.add_argument("--venv", type=Path, default=Path(".venv"))
    parser.add_argument("--extras", default="full", help="Optional dependency extra (default: full)")
    parser.add_argument("--index-url", help="Approved internal Python package index")
    parser.add_argument("--find-links", type=Path, help="Offline wheelhouse directory")
    args = parser.parse_args()

    wheel = args.wheel.resolve()
    venv_root = args.venv.resolve()
    if not wheel.is_file() or wheel.suffix != ".whl":
        parser.error(f"approved wheel does not exist or is not a .whl file: {wheel}")
    if args.index_url and args.find_links:
        parser.error("use either --index-url or --find-links, not both")
    if venv_root.exists():
        parser.error(f"refusing to reuse existing virtual environment: {venv_root}")

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
    print(f"Install complete. Activate: {venv_root / ('Scripts/Activate.ps1' if sys.platform == 'win32' else 'bin/activate')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
