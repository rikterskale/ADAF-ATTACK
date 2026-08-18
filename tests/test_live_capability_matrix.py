from __future__ import annotations

import json
from pathlib import Path

from scripts.validate_live_capability_matrix import validate_matrix

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs" / "LIVE_CAPABILITY_MATRIX.json"


def test_live_capability_matrix_covers_registry() -> None:
    assert validate_matrix(MATRIX) == []


def test_live_capability_matrix_rejects_missing_capability(tmp_path: Path) -> None:
    payload = json.loads(MATRIX.read_text(encoding="utf-8"))
    payload["capabilities"].pop("ldap-enum")
    path = tmp_path / "matrix.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert any("ldap-enum" in error for error in validate_matrix(path))


def test_live_capability_matrix_rejects_missing_rollback_for_destructive(tmp_path: Path) -> None:
    payload = json.loads(MATRIX.read_text(encoding="utf-8"))
    payload["capabilities"]["acl-write"]["rollback"] = "not-required"
    path = tmp_path / "matrix.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert any("acl-write" in error for error in validate_matrix(path))
