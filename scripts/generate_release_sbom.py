#!/usr/bin/env python3
"""Generate a CycloneDX SBOM from an exact wheel's operator environment."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import venv
from collections.abc import Sequence
from pathlib import Path
from typing import Any

REQUIRED_COMPONENTS = {
    "adaf-attack",
    "impacket",
    "pypdf",
    "reportlab",
    "textual",
}
FORBIDDEN_COMPONENTS = {
    "bandit",
    "build",
    "mypy",
    "pip-audit",
    "pre-commit",
    "pytest",
    "pytest-cov",
    "ruff",
    "twine",
}


def _run(command: Sequence[str]) -> None:
    subprocess.run(command, check=True)


def _venv_python(venv_dir: Path) -> Path:
    if sys.platform == "win32":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _site_packages(python: Path) -> Path:
    completed = subprocess.run(
        [
            str(python),
            "-c",
            (
                "import json, site; "
                "print(json.dumps([item for item in site.getsitepackages() "
                "if item.endswith(('site-packages', 'dist-packages'))]))"
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    candidates = json.loads(completed.stdout)
    if not candidates:
        raise RuntimeError("Could not locate the release environment site-packages")
    return Path(candidates[0])


def _distribution_version(python: Path) -> str:
    completed = subprocess.run(
        [
            str(python),
            "-c",
            "from importlib.metadata import version; print(version('adaf-attack'))",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _component_names(document: dict[str, Any]) -> set[str]:
    components = document.get("components")
    if not isinstance(components, list):
        raise ValueError("SBOM does not contain a CycloneDX components list")
    names = {
        str(component.get("name", "")).lower().replace("_", "-").replace(".", "-")
        for component in components
        if isinstance(component, dict)
    }
    metadata = document.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("component"), dict):
        name = str(metadata["component"].get("name", ""))
        names.add(name.lower().replace("_", "-").replace(".", "-"))
    return names


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _add_root_component(path: Path, wheel: Path, version: str) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    components = document.setdefault("components", [])
    if not isinstance(components, list):
        raise ValueError("SBOM does not contain a CycloneDX components list")
    purl = f"pkg:pypi/adaf-attack@{version}"
    root_component = {
        "bom-ref": purl,
        "type": "application",
        "name": "adaf-attack",
        "version": version,
        "hashes": [{"alg": "SHA-256", "content": _sha256(wheel)}],
        "purl": purl,
    }
    components[:] = [
        component
        for component in components
        if not isinstance(component, dict)
        or str(component.get("name", "")).lower().replace("_", "-") != "adaf-attack"
    ]
    metadata = document.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("SBOM metadata must be an object")
    metadata["component"] = root_component
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def validate_release_sbom(path: Path) -> None:
    """Verify that the SBOM represents the supported operator environment."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("bomFormat") != "CycloneDX":
        raise ValueError("SBOM is not a CycloneDX document")
    names = _component_names(document)
    missing = REQUIRED_COMPONENTS - names
    if missing:
        raise ValueError(f"SBOM is missing operator components: {sorted(missing)}")
    forbidden = FORBIDDEN_COMPONENTS & names
    if forbidden:
        raise ValueError(f"SBOM contains development-only components: {sorted(forbidden)}")


def generate_release_sbom(wheel: Path, output: Path, venv_dir: Path) -> None:
    """Install the exact wheel with operator extras and inventory that environment."""
    if not wheel.is_file() or wheel.suffix != ".whl":
        raise FileNotFoundError(f"Release wheel not found: {wheel}")
    if venv_dir.exists():
        raise FileExistsError(f"SBOM environment already exists: {venv_dir}")

    venv.EnvBuilder(with_pip=True).create(venv_dir)
    python = _venv_python(venv_dir)
    _run(
        [
            str(python),
            "-m",
            "pip",
            "--disable-pip-version-check",
            "install",
            f"{wheel.resolve()}[operator]",
        ]
    )
    _run([str(python), "-m", "pip", "check"])
    version = _distribution_version(python)
    _run([str(python), "-m", "pip", "uninstall", "--yes", "pip"])
    output.parent.mkdir(parents=True, exist_ok=True)
    _run(
        [
            sys.executable,
            "-m",
            "pip_audit",
            "--path",
            str(_site_packages(python)),
            "--format",
            "cyclonedx-json",
            "--output",
            str(output),
        ]
    )
    _add_root_component(output, wheel, version)
    validate_release_sbom(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--venv", required=True, type=Path)
    args = parser.parse_args()

    generate_release_sbom(args.wheel, args.output, args.venv)
    print(f"Release SBOM: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
