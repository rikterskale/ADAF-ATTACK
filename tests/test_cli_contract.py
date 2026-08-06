"""Stable human/JSON CLI UX contracts."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from adaf_attack.cli import app

runner = CliRunner()


def test_doctor_json_has_stable_remediation_contract() -> None:
    result = runner.invoke(app, ["--format", "json", "doctor", "--explain"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert {"ok", "version", "checks", "next_step"} <= payload.keys()
    assert all(
        {"id", "status", "value", "remediation"} <= check.keys() for check in payload["checks"]
    )


def test_plan_json_explicitly_reports_destructive_risk() -> None:
    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "plan",
            "shadow-creds",
            "--domain",
            "corp.example",
            "--dc-ip",
            "10.0.0.10",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["mode"] == "preview"
    assert payload["risk"] == {
        "force_provided": False,
        "level": "high",
        "may_modify_target": True,
        "network_contact": True,
        "requires_force": True,
    }
    assert payload["next_step"].endswith(" --force")


def test_unknown_capability_uses_actionable_json_error() -> None:
    result = runner.invoke(app, ["--format", "json", "capability-help", "not-a-capability"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["error"]["code"] == "UNKNOWN_CAPABILITY"
    assert "capability-help" in payload["error"]["remediation"]


def test_sessions_json_is_read_only_cleanup_status(tmp_path: object) -> None:
    result = runner.invoke(app, ["--format", "json", "sessions", "--workspace", str(tmp_path)])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["cleanup"]["action"] == "read-only status"
    assert payload["cleanup"]["session_count"] == 0
