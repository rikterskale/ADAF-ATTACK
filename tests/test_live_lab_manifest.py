from __future__ import annotations

import json
from pathlib import Path

from scripts.validate_live_lab_manifest import validate_manifest

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "docs" / "LIVE_LAB_MANIFEST.template.json"


def test_lab_manifest_template_is_safe_and_valid() -> None:
    assert validate_manifest(TEMPLATE) == []


def test_lab_manifest_rejects_public_dc_ip(tmp_path: Path) -> None:
    payload = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    payload["dc_ip"] = "8.8.8.8"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert any("private" in error for error in validate_manifest(path))


def test_lab_manifest_rejects_credentials(tmp_path: Path) -> None:
    payload = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    payload["password"] = "do-not-add-secrets"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert any("credentials" in error for error in validate_manifest(path))
