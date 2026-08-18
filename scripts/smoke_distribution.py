#!/usr/bin/env python3
"""Install one distribution artifact in a clean venv and exercise the public CLI."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import venv
from pathlib import Path


def _venv_python(root: Path) -> Path:
    if os.name == "nt":
        return root / "Scripts" / "python.exe"
    return root / "bin" / "python"


def _venv_cli(root: Path) -> Path:
    if os.name == "nt":
        return root / "Scripts" / "adaf-attack.exe"
    return root / "bin" / "adaf-attack"


def _run(command: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    print("+", subprocess.list2cmdline(command), flush=True)
    return subprocess.run(
        command,
        check=True,
        text=True,
        capture_output=capture,
    )


def smoke(artifact: Path, venv_root: Path, extras: str | None) -> None:
    artifact = artifact.resolve()
    if not artifact.is_file():
        raise FileNotFoundError(f"distribution artifact does not exist: {artifact}")
    if venv_root.exists():
        raise FileExistsError(f"smoke environment must be clean: {venv_root}")

    venv.EnvBuilder(with_pip=True, clear=False).create(venv_root)
    python = _venv_python(venv_root)
    cli = _venv_cli(venv_root)
    _run([str(python), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"])
    requirement = str(artifact)
    if extras:
        requirement = f"{requirement}[{extras}]"
    _run([str(python), "-m", "pip", "install", requirement])
    _run([str(python), "-m", "pip", "check"])
    _run(
        [
            str(python),
            "-c",
            (
                "from importlib.metadata import version; "
                "import adaf_attack; "
                "assert version('adaf-attack') == adaf_attack.__version__; "
                "print(adaf_attack.__version__)"
            ),
        ]
    )
    if not cli.is_file():
        raise FileNotFoundError(f"console entry point was not installed: {cli}")

    _run([str(cli), "--version"])
    for arguments in (
        ["--format", "json", "doctor", "--explain"],
        ["--format", "json", "doctor", "--profile", "user-readiness"],
        ["--format", "json", "list-capabilities"],
        ["--format", "json", "paths"],
    ):
        result = _run([str(cli), *arguments], capture=True)
        payload = json.loads(result.stdout)
        if payload.get("ok") is not True:
            raise RuntimeError(f"{arguments[-1]} returned ok != true: {payload}")

    demo_root = venv_root.parent / f"{venv_root.name}-demo"
    demo = _run([str(cli), "--format", "json", "demo", "--workspace", str(demo_root)], capture=True)
    demo_payload = json.loads(demo.stdout)
    if demo_payload.get("ok") is not True:
        raise RuntimeError(f"packaged demo failed: {demo_payload}")
    session = demo_payload["session_path"]
    if extras in {"full", "operator", "reports"}:
        _run(
            [
                str(cli),
                "engagement",
                "report",
                "--session",
                session,
                "--engagement-id",
                "SMOKE-2026-001",
            ]
        )
        _run(
            [
                str(cli),
                "engagement",
                "package",
                "--session",
                session,
                "--output",
                str(demo_root / "demo-package.zip"),
                "--profile",
                "client",
            ]
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--venv", type=Path, required=True)
    parser.add_argument("--extras")
    args = parser.parse_args()
    smoke(args.artifact, args.venv, args.extras)
    return 0


if __name__ == "__main__":
    sys.exit(main())
