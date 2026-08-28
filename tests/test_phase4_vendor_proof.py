"""Phase 4 vendor-proof behavioral checks for the guided spine and contracts.

These tests lock operator-facing contracts. They do not assert scorecard prose
or marketing slogans — scores live in docs/VENDOR_SCORECARD.md and must be
backed by the behaviors below (and MANUAL evidence for stranger proofs).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from adaf_attack.cli import _doctor_payload, app
from adaf_attack.core.cli_contract import ERROR_CATALOG, classify_run_error
from adaf_attack.core.journey import STAGE_LABELS

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _consistent_test_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    import adaf_attack.cli as cli

    monkeypatch.setattr(
        cli, "_pip_consistency_check", lambda: (True, "No broken requirements found.")
    )


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


def test_installer_and_approval_codes_are_in_error_catalog() -> None:
    for code in (
        "PYTHON_UNSUPPORTED",
        "PATH_NOT_FOUND",
        "EXECUTION_POLICY_BLOCKED",
        "PROXY_TLS_FAILED",
        "INSTALLER_FAILURE",
        "INSTALLER_OWNERSHIP",
        "GUIDE_ADVANCE_UNSAFE",
        "APPROVAL_TOKEN_EXPIRED",
        "APPROVAL_TOKEN_INVALID",
        "VERSION_SKEW",
        "KALI_REQUIRED",
        "SECRET_IN_OUTPUT",
    ):
        assert code in ERROR_CATALOG


def test_real_approval_messages_classify_to_catalog_codes() -> None:
    assert classify_run_error("Approval token has expired") == "APPROVAL_TOKEN_EXPIRED"
    assert (
        classify_run_error("Scoped approval rejected: Approval token signature is invalid")
        == "APPROVAL_TOKEN_INVALID"
    )


def test_windows_installer_json_includes_recovery_command() -> None:
    text = (ROOT / "scripts" / "Install-AdafAttack.ps1").read_text(encoding="utf-8")
    assert "recovery_command" in text
    assert "function Fail-Adaf" in text


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
    what_next = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "what-next",
                "--workspace",
                str(workspace),
                "--session",
                str(session),
            ],
        )
    )
    workflow_next = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "workflow",
                "next",
                "--workspace",
                str(workspace),
                "--session",
                str(session),
            ],
        )
    )
    tour = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "tour",
                "--workspace",
                str(workspace),
                "--session",
                str(session),
            ],
        )
    )
    home = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "home",
                "--workspace",
                str(workspace),
                "--session",
                str(session),
            ],
        )
    )
    help_me = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "help-me",
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
    assert what_next["suggested_command"] == guide["suggested_command"]
    assert workflow_next["suggested_command"] == guide["suggested_command"]
    assert workflow_next["recommendations"][0]["suggested_command"] == guide["suggested_command"]
    assert tour["suggested_command"] == guide["suggested_command"]
    assert home["suggested_command"] == guide["suggested_command"]
    assert help_me["suggested_command"] == guide["suggested_command"]
    assert tour["recovery_command"] == guide["recovery_command"]
    assert home["recovery_command"] == guide["recovery_command"]
    assert help_me["recovery_command"] == guide["recovery_command"]


def test_safe_only_phase_catalog_contract_is_complete() -> None:
    payload = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "list-capabilities",
                "--by-phase",
                "--safe-only",
            ],
        )
    )
    assert payload["ok"] is True
    assert payload["by_phase"] is True
    assert payload["safe_only"] is True
    grouped_ids = [
        capability_id for phase in payload["phases"] for capability_id in phase["capability_ids"]
    ]
    listed_ids = [capability["id"] for capability in payload["capabilities"]]
    assert grouped_ids
    assert grouped_ids == listed_ids
    assert payload["count"] == len(listed_ids)


def test_operator_docs_carry_stage_labels_and_first_ten_canon() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for label in STAGE_LABELS.values():
        assert label in readme, f"README missing stage label {label!r}"
    assert "Ready / Blocked / Failed / Done" in readme
    # Contiguous first-ten canon (may be preceded by an install line).
    canon = (
        "python -m pip check\n"
        "adaf-attack --version\n"
        "adaf-attack --format json doctor --profile user-readiness --explain\n"
        "adaf-attack quickstart --workspace ./quickstart\n"
        "adaf-attack --format json guide --workspace ./quickstart --session ./quickstart/demo-session\n"
        "adaf-attack --format json paths"
    )
    assert canon in readme
    evidence = (ROOT / "docs" / "RELEASE_EVIDENCE.md").read_text(encoding="utf-8")
    assert "## 6. Narrow-terminal TUI spot-check" in evidence
    assert "Do **not** invent a public package URL" in evidence
    assert "RELEASE_EVIDENCE_0.10.1.md" in evidence
    published = (ROOT / "docs" / "RELEASE_EVIDENCE_0.10.1.md").read_text(encoding="utf-8")
    assert "7e5bbc74c48dca50277e92f59535dcb8cc4ee192" in published
    assert "33112303284" in published
    assert "Manual evidence not captured" in published
    scorecard = (ROOT / "docs" / "VENDOR_SCORECARD.md").read_text(encoding="utf-8")
    assert "RELEASE_EVIDENCE_0.10.1.md" in scorecard
    assert "../tmp/" not in scorecard
