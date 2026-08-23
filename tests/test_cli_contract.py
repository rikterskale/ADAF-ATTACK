"""Stable human/JSON CLI UX contracts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

import adaf_attack.cli as cli
from adaf_attack.cli import app
from adaf_attack.core.runner import RunError

runner = CliRunner()


def test_doctor_json_has_stable_remediation_contract() -> None:
    result = runner.invoke(app, ["--format", "json", "doctor", "--explain"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert {"ok", "version", "checks", "next_step"} <= payload.keys()
    assert all(
        {"id", "status", "value", "remediation"} <= check.keys() for check in payload["checks"]
    )


def test_plan_json_reports_read_only_default_for_mixed_capability() -> None:
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
        "level": "observe",
        "may_modify_target": False,
        "network_contact": True,
        "requires_force": False,
    }
    assert not payload["next_step"].endswith(" --force")


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


def test_version_json_is_machine_readable() -> None:
    result = runner.invoke(app, ["--format", "json", "--version"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert isinstance(payload["version"], str)


def test_paths_json_has_all_workspace_locations() -> None:
    result = runner.invoke(app, ["--format", "json", "paths"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert {"platform", "data", "config", "workspace"} <= payload.keys()


def test_list_capabilities_json_exposes_safe_metadata() -> None:
    result = runner.invoke(app, ["--format", "json", "list-capabilities"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["count"] == len(payload["capabilities"])
    assert {"id", "category", "summary", "destructive"} <= payload["capabilities"][0].keys()


def test_known_capability_help_includes_execution_contract() -> None:
    result = runner.invoke(app, ["--format", "json", "capability-help", "acl-enum"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["capability"]["id"] == "acl-enum"
    assert payload["capability"]["next_step"].startswith("Run `adaf-attack plan acl-enum --domain")


def test_invalid_output_format_is_rejected() -> None:
    result = runner.invoke(app, ["--format", "yaml", "doctor"])

    assert result.exit_code != 0
    assert "summary" in result.output
    assert "beginner" in result.output


def test_run_json_forwards_capability_options_to_runner(monkeypatch: Any, tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    def fake_run(capability: str, target: Any, **kwargs: Any) -> dict[str, Any]:
        seen.update({"capability": capability, "target": target, **kwargs})
        return {"session_path": str(tmp_path), "ok": True}

    monkeypatch.setattr(cli, "execute_capability", fake_run)
    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "run",
            "ldap-enum",
            "--domain",
            "corp.test",
            "--dc-ip",
            "192.0.2.10",
            "--scope",
            "domain",
            "--max-objects",
            "12",
            "--write-target",
            "CN=Alice",
            "--value",
            "x",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["ok"] is True
    assert seen["capability"] == "ldap-enum"
    assert seen["scope"] == "domain" and seen["max_objects"] == 12
    assert seen["write_target"] == "CN=Alice" and seen["value"] == "x"


def test_run_json_converts_runner_errors_to_actionable_contract(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        cli,
        "execute_capability",
        lambda *args, **kwargs: (_ for _ in ()).throw(RunError("Unknown capability: nope")),
    )
    result = runner.invoke(
        app, ["--format", "json", "run", "nope", "--domain", "corp.test", "--dc-ip", "192.0.2.10"]
    )

    assert result.exit_code == 1
    assert json.loads(result.output)["error"]["code"] == "UNKNOWN_CAPABILITY"
