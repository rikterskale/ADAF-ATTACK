"""Contract tests for release manifests and reproducible wheelhouse metadata."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


def _load_manifest_module():
    path = Path(__file__).parents[1] / "scripts" / "generate_release_manifest.py"
    spec = importlib.util.spec_from_file_location("generate_release_manifest", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_manifest_records_artifact_and_wheelhouse_hashes(tmp_path: Path) -> None:
    module = _load_manifest_module()
    repo = tmp_path / "repo"
    dist = repo / "dist"
    wheelhouse = repo / "wheelhouse"
    dist.mkdir(parents=True)
    wheelhouse.mkdir()
    (repo / "pyproject.toml").write_text(
        "[project]\n"
        "name = \"adaf-attack\"\n"
        "version = \"9.9.9\"\n"
        "requires-python = \">=3.11,<3.14\"\n"
        "dependencies = []\n"
        "[project.optional-dependencies]\n"
        "full = [\"example==1.0\"]\n",
        encoding="utf-8",
    )
    artifact = dist / "adaf_attack-9.9.9-py3-none-any.whl"
    dependency = wheelhouse / "example-1.0-py3-none-any.whl"
    artifact.write_bytes(b"artifact")
    dependency.write_bytes(b"dependency")

    manifest = module.build_manifest(repo, dist, wheelhouse)
    module.validate_manifest(manifest, dist=dist, wheelhouse=wheelhouse)

    assert manifest["version"] == "9.9.9"
    assert manifest["requires_python"] == ">=3.11,<3.14"
    assert manifest["extras"]["full"] == ["example==1.0"]
    assert manifest["artifacts"][0]["filename"] == artifact.name
    assert manifest["wheelhouse"][0]["filename"] == dependency.name


def test_manifest_rejects_tampered_artifact(tmp_path: Path) -> None:
    module = _load_manifest_module()
    repo = tmp_path / "repo"
    dist = repo / "dist"
    dist.mkdir(parents=True)
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "adaf-attack"\nversion = "1.0.0"\n'
        'requires-python = ">=3.11,<3.14"\n',
        encoding="utf-8",
    )
    artifact = dist / "adaf_attack-1.0.0-py3-none-any.whl"
    artifact.write_bytes(b"original")
    manifest = module.build_manifest(repo, dist, None)
    artifact.write_bytes(b"tampered")

    with pytest.raises(ValueError, match="checksum mismatch"):
        module.validate_manifest(manifest, dist=dist)


def test_manifest_json_is_stable_and_readable(tmp_path: Path) -> None:
    module = _load_manifest_module()
    repo = tmp_path / "repo"
    dist = repo / "dist"
    dist.mkdir(parents=True)
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "adaf-attack"\nversion = "1.0.0"\n'
        'requires-python = ">=3.11,<3.14"\n',
        encoding="utf-8",
    )
    (dist / "adaf_attack-1.0.0-py3-none-any.whl").write_bytes(b"artifact")
    manifest = module.build_manifest(repo, dist, None)
    output = tmp_path / "release-manifest.json"
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert json.loads(output.read_text(encoding="utf-8"))["schema"] == 1
