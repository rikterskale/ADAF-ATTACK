from __future__ import annotations

import json
from pathlib import Path

from scripts.validate_live_lab_run import validate_bundle, validate_release_record


def _record() -> dict[str, object]:
    return {
        "schema_version": 1,
        "release_version": "0.10.0",
        "commit_sha": "a" * 40,
        "lab_snapshot": "clean-domain",
        "operator_os": "Kali",
        "operator_python": "3.12.4",
        "optional_capabilities": [{"name": "ldap-enum", "status": "pass"}],
        "read_only_smoke": "pass",
        "force_guard": "pass",
        "mutation_rollback": "not_run",
        "evidence_validator": "pass",
        "sanitized_evidence_location": "release-artifacts/live-lab.zip",
        "reviewer": "maintainer",
        "review_date": "2026-08-18",
    }


def test_release_record_validates(tmp_path: Path) -> None:
    record = tmp_path / "release-evidence.json"
    record.write_text(json.dumps(_record()), encoding="utf-8")
    assert validate_release_record(record) == []


def test_release_record_rejects_unredacted_sensitive_value(tmp_path: Path) -> None:
    payload = _record()
    payload["password"] = "secret"
    record = tmp_path / "release-evidence.json"
    record.write_text(json.dumps(payload), encoding="utf-8")
    errors = validate_release_record(record)
    assert any("possible unredacted secret" in error for error in errors)


def test_release_record_rejects_unknown_capability(tmp_path: Path) -> None:
    record = tmp_path / "release-evidence.json"
    payload = _record()
    payload["optional_capabilities"] = [{"name": "not-registered", "status": "pass"}]
    record.write_text(json.dumps(payload), encoding="utf-8")
    matrix = tmp_path / "matrix.json"
    matrix.write_text(json.dumps({"capabilities": {"ldap-enum": {}}}), encoding="utf-8")
    errors = validate_release_record(record, matrix)
    assert any("not in the live capability matrix" in error for error in errors)


def test_bundle_can_validate_record_and_required_files(tmp_path: Path) -> None:
    (tmp_path / "findings.json").write_text("{}", encoding="utf-8")
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "report-manifest.json").write_text("{}", encoding="utf-8")
    record = tmp_path / "release-evidence.json"
    record.write_text(json.dumps(_record()), encoding="utf-8")
    assert validate_bundle(tmp_path, ["findings.json", "reports/report-manifest.json"]) == []
    assert validate_release_record(record) == []
