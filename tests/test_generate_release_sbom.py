from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.generate_release_sbom import (
    REQUIRED_COMPONENTS,
    _add_root_component,
    validate_release_sbom,
)


def _write_sbom(path: Path, names: set[str]) -> None:
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [{"name": name} for name in sorted(names)],
            }
        ),
        encoding="utf-8",
    )


def test_release_sbom_accepts_operator_environment(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom, REQUIRED_COMPONENTS | {"typer", "rich"})

    validate_release_sbom(sbom)


def test_release_sbom_rejects_missing_operator_component(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom, REQUIRED_COMPONENTS - {"textual"})

    with pytest.raises(ValueError, match="textual"):
        validate_release_sbom(sbom)


def test_release_sbom_rejects_development_component(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom, REQUIRED_COMPONENTS | {"pytest"})

    with pytest.raises(ValueError, match="development-only.*pytest"):
        validate_release_sbom(sbom)


def test_release_sbom_records_exact_wheel_as_root_component(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.json"
    wheel = tmp_path / "adaf_attack-1.2.3-py3-none-any.whl"
    wheel.write_bytes(b"exact wheel bytes")
    _write_sbom(sbom, REQUIRED_COMPONENTS - {"adaf-attack"})

    _add_root_component(sbom, wheel, "1.2.3")

    document = json.loads(sbom.read_text(encoding="utf-8"))
    root = document["metadata"]["component"]
    assert root["name"] == "adaf-attack"
    assert root["version"] == "1.2.3"
    assert root["hashes"] == [
        {"alg": "SHA-256", "content": hashlib.sha256(wheel.read_bytes()).hexdigest()}
    ]
    validate_release_sbom(sbom)
