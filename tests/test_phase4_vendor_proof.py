"""Phase 4 vendor-proof behavioral checks for the guided spine and contracts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from adaf_attack.cli import _doctor_payload, app
from adaf_attack.core.cli_contract import ERROR_CATALOG

runner = CliRunner()


def _json(result: Any) -> dict[str, Any]:
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def test_doctor_ready_contract_for_user_readiness() -> None:
    payload = _doctor_payload("user-readiness")
    assert payload["ok"] is True
    assert payload["ready"] is True
    assert payload["readiness"]["ready"] is True
    assert payload["readiness"]["next_command"] == "adaf-attack guide"
    for check in payload["checks"]:
        assert isinstance(check.get("remediation"), str) and check["remediation"].strip()


def test_emit_error_always_includes_guide_recovery(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    result = runner.invoke(app, ["--format", "json", "explain", "not-a-real-capability"])
    assert result.exit_code != 0
    payload = json.loads(result.output)
    error = payload["error"]
    assert error["code"] == "UNKNOWN_CAPABILITY"
    assert error.get("recovery_command", "").startswith("adaf-attack guide")


def test_installer_codes_are_in_error_catalog() -> None:
    for code in (
        "PYTHON_UNSUPPORTED",
        "PATH_NOT_FOUND",
        "EXECUTION_POLICY_BLOCKED",
        "PROXY_TLS_FAILED",
        "INSTALLER_FAILURE",
        "INSTALLER_OWNERSHIP",
        "GUIDE_ADVANCE_UNSAFE",
    ):
        assert code in ERROR_CATALOG


def test_first_ten_minutes_guide_payload_is_copy_ready(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    workspace = tmp_path / "quickstart"
    quick = _json(
        runner.invoke(app, ["--format", "json", "quickstart", "--workspace", str(workspace)])
    )
    assert quick["ok"] is True
    session = Path(quick["session_path"])
    guide = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "guide",
                "--workspace",
                str(workspace),
                "--session",
                str(session),
            ],
        )
    )
    assert guide["ok"] is True
    assert guide["suggested_command"] == guide["next_step"]
    assert guide["primary_action"]["suggested_command"].startswith("adaf-attack ")
    assert guide["recovery_command"].startswith("adaf-attack guide")
    assert guide["primary_action"]["risk"]
    assert "rollback_implication" in guide["primary_action"]


def test_vendor_scorecard_and_evidence_docs_exist() -> None:
    root = Path(__file__).resolve().parents[1]
    scorecard = (root / "docs" / "VENDOR_SCORECARD.md").read_text(encoding="utf-8")
    assert "No row below 9" in scorecard
    assert "Vendor SE first-ten-minutes script" in scorecard
    evidence = (root / "docs" / "RELEASE_EVIDENCE.md").read_text(encoding="utf-8")
    assert "## 5. Security disclosure path check" in evidence
