#!/usr/bin/env python3
"""Install one distribution artifact in a clean venv and exercise the public CLI."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import venv
from functools import partial
from pathlib import Path


def _venv_python(root: Path) -> Path:
    if os.name == "nt":
        return root / "Scripts" / "python.exe"
    return root / "bin" / "python"


def _venv_cli(root: Path) -> Path:
    if os.name == "nt":
        return root / "Scripts" / "adaf-attack.exe"
    return root / "bin" / "adaf-attack"


def _run(
    command: list[str], *, capture: bool = False, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    print("+", subprocess.list2cmdline(command), flush=True)
    return subprocess.run(
        command,
        check=True,
        text=True,
        capture_output=capture,
        env=env,
        encoding="utf-8",
        timeout=180,
    )


def smoke(
    artifact: Path, venv_root: Path, extras: str | None, find_links: Path | None = None
) -> None:
    artifact = artifact.resolve()
    venv_root = venv_root.resolve()
    if not artifact.is_file():
        raise FileNotFoundError(f"distribution artifact does not exist: {artifact}")
    if venv_root.exists():
        raise FileExistsError(f"smoke environment must be clean: {venv_root}")
    if find_links is not None and not find_links.is_dir():
        raise FileNotFoundError(f"wheelhouse directory does not exist: {find_links}")

    state_root = venv_root.parent / f"{venv_root.name}-state"
    environment = {
        **os.environ,
        "PYTHONUTF8": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "ADAF_ATTACK_DATA_DIR": str(state_root / "data"),
        "ADAF_ATTACK_CONFIG_DIR": str(state_root / "config"),
        "ADAF_ATTACK_WORKSPACE": str(state_root / "workspace"),
    }
    # Avoid checkout imports or dependency leakage into the candidate environment.
    environment.pop("PYTHONPATH", None)
    if find_links is not None:
        environment.update({"PIP_NO_INDEX": "1", "PIP_FIND_LINKS": find_links.resolve().as_uri()})
    run = partial(_run, env=environment)

    venv.EnvBuilder(with_pip=True, clear=False).create(venv_root)
    python = _venv_python(venv_root)
    cli = _venv_cli(venv_root)
    # Wheel installs only need the pip provided by venv. Building sdists uses
    # the pinned build requirements in pyproject.toml through build isolation.
    project = f"adaf-attack[{extras}]" if extras and extras != "base" else "adaf-attack"
    requirement = f"{project} @ {artifact.as_uri()}"
    run([str(python), "-m", "pip", "install", requirement])
    run([str(python), "-m", "pip", "check"])
    run(
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

    run([str(cli), "--version"])
    doctor_payload: dict[str, object] | None = None
    for arguments in (
        ["--format", "json", "doctor", "--explain"],
        ["--format", "json", "doctor", "--profile", "user-readiness", "--explain"],
        ["--format", "json", "list-capabilities"],
        ["--format", "json", "paths"],
    ):
        result = run([str(cli), *arguments], capture=True)
        payload = json.loads(result.stdout)
        if payload.get("ok") is not True:
            raise RuntimeError(f"{arguments[-1]} returned ok != true: {payload}")
        if "user-readiness" in arguments:
            doctor_payload = payload
    if doctor_payload is None or doctor_payload.get("ready") is not True:
        raise RuntimeError(f"user-readiness doctor did not report ready: {doctor_payload}")
    readiness = doctor_payload.get("readiness")
    if not isinstance(readiness, dict) or readiness.get("ready") is not True:
        raise RuntimeError(f"nested readiness contract did not report ready: {doctor_payload}")

    demo_root = venv_root.parent / f"{venv_root.name}-demo"
    quickstart = run(
        [str(cli), "--format", "json", "quickstart", "--workspace", str(demo_root / "quickstart")],
        capture=True,
    )
    quickstart_payload = json.loads(quickstart.stdout)
    if quickstart_payload.get("ok") is not True:
        raise RuntimeError(f"first-run quickstart failed: {quickstart_payload}")
    session = str(quickstart_payload["session_path"])
    guide = run(
        [
            str(cli),
            "--format",
            "json",
            "guide",
            "--workspace",
            str(demo_root / "quickstart"),
            "--session",
            session,
        ],
        capture=True,
    )
    guide_payload = json.loads(guide.stdout)
    if guide_payload.get("ok") is not True or not guide_payload.get("suggested_command"):
        raise RuntimeError(f"first-run guide failed: {guide_payload}")
    # Every orientation surface must agree for the new operator's same session.
    for command in (["what-next"], ["workflow", "next"], ["tour"], ["home"]):
        result = run(
            [
                str(cli),
                "--format",
                "json",
                *command,
                "--workspace",
                str(demo_root / "quickstart"),
                "--session",
                session,
            ],
            capture=True,
        )
        payload = json.loads(result.stdout)
        if (
            payload.get("ok") is not True
            or payload.get("suggested_command") != guide_payload["suggested_command"]
        ):
            raise RuntimeError(f"orientation disagrees with guide: {command}: {payload}")
    demo = run([str(cli), "--format", "json", "demo", "--workspace", str(demo_root)], capture=True)
    demo_payload = json.loads(demo.stdout)
    if demo_payload.get("ok") is not True:
        raise RuntimeError(f"packaged demo failed: {demo_payload}")
    session = demo_payload["session_path"]
    if extras in {"full", "operator", "reports"}:
        run(
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
        run(
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
    parser.add_argument(
        "--find-links", type=Path, help="Install offline from a complete wheelhouse"
    )
    args = parser.parse_args()
    smoke(args.artifact, args.venv, args.extras, args.find_links)
    return 0


if __name__ == "__main__":
    sys.exit(main())
