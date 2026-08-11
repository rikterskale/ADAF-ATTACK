"""Tests for the ten UX feature enhancements."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from adaf_attack.cli import app
from adaf_attack.core import profiles as profiles_mod
from adaf_attack.core import user_config
from adaf_attack.core.cli_contract import error_for
from adaf_attack.core.completions import generate_completion
from adaf_attack.core.ux import (
    capability_prerequisites,
    export_plan_markdown,
    format_next_actions_block,
    format_stages_progress,
)

runner = CliRunner()


def test_error_catalog_includes_suggested_command() -> None:
    err = error_for("UNKNOWN_CAPABILITY")
    assert err.suggested_command
    payload = err.payload()["error"]
    assert payload["suggested_command"]


def test_profile_set_list_use_delete(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(profiles_mod, "profiles_path", lambda: tmp_path / "profiles.json")
    monkeypatch.setattr(user_config, "config_path", lambda: tmp_path / "config.json")

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "profile",
            "set",
            "lab",
            "--domain",
            "corp.lab",
            "--dc-ip",
            "10.0.0.10",
            "--opsec",
            "stealth",
            "--default",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["profile"]["domain"] == "corp.lab"
    assert payload["profile"]["opsec_profile"] == "stealth"
    assert payload["default"] is True

    listed = runner.invoke(app, ["--format", "json", "profile", "list"])
    assert listed.exit_code == 0
    listed_payload = json.loads(listed.output)
    assert listed_payload["count"] == 1
    assert listed_payload["default"] == "lab"

    used = runner.invoke(app, ["--format", "json", "profile", "use", "lab"])
    assert used.exit_code == 0

    deleted = runner.invoke(app, ["--format", "json", "profile", "delete", "lab"])
    assert deleted.exit_code == 0


def test_completions_bash() -> None:
    script = generate_completion("bash")
    assert "complete -F" in script
    result = runner.invoke(app, ["--format", "json", "completions", "bash"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["shell"] == "bash"
    assert "script" in payload


def test_capability_help_includes_prerequisites() -> None:
    result = runner.invoke(app, ["--format", "json", "capability-help", "shadow-creds"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "prerequisites" in payload["capability"]
    assert "suggested_next" in payload["capability"]


def test_plan_export(tmp_path: Path) -> None:
    export_path = tmp_path / "plan.md"
    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "plan",
            "ldap-enum",
            "-d",
            "corp.example",
            "--dc-ip",
            "10.0.0.10",
            "--export",
            str(export_path),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["export"] == str(export_path)
    assert export_path.is_file()
    content = export_path.read_text(encoding="utf-8")
    assert "ldap-enum" in content
    assert "Copy-ready command" in content


def test_demo_offline(tmp_path: Path) -> None:
    result = runner.invoke(app, ["--format", "json", "demo", "--workspace", str(tmp_path)])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["mode"] == "offline-demo"
    assert Path(payload["session_path"]).is_dir()


def test_session_show_dashboard(tmp_path: Path) -> None:
    session = tmp_path / "s1"
    session.mkdir()
    (session / "session.json").write_text(
        json.dumps({"session_id": "s1", "created_at": "2026-08-01T00:00:00+00:00"}),
        encoding="utf-8",
    )
    (session / "findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {"id": "f1", "title": "DCSync principal", "severity": "high"},
                    {"id": "f2", "title": "Open share", "severity": "low"},
                ]
            }
        ),
        encoding="utf-8",
    )
    (session / "graph.json").write_text(
        json.dumps({"summary": {"nodes": 3, "edges": 2}}), encoding="utf-8"
    )
    result = runner.invoke(
        app,
        ["--format", "json", "session", "show", "--session", str(session), "--severity", "high"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["finding_count"] == 2
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["severity"] == "high"


def test_ux_helpers_prereqs_and_stages() -> None:
    import adaf_attack.capabilities  # noqa: F401
    from adaf_attack.core.registry import capability_registry

    cap = capability_registry.get("shadow-creds")
    assert cap is not None
    prereqs = capability_prerequisites("shadow-creds")
    assert "best_run_after" in prereqs
    stages = format_stages_progress(cap, current="execute")
    assert stages["stages"]
    nxt = format_next_actions_block(cap, domain="corp.lab", dc_ip="10.0.0.10")
    assert "suggestions" in nxt
    md = export_plan_markdown(
        capability_id="shadow-creds",
        domain="corp.lab",
        dc_ip="10.0.0.10",
        risk={"level": "high", "may_modify_target": True, "requires_force": True},
        checklist={"opsec_hint": "Prefer stealth", "items": [{"label": "Scope", "required": True}]},
        ready_command="adaf-attack run shadow-creds --force",
        prerequisites=prereqs,
    )
    assert "shadow-creds" in md


def test_errors_command_shows_suggested() -> None:
    result = runner.invoke(app, ["--format", "json", "errors", "UNKNOWN_CAPABILITY"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["errors"][0].get("suggested_command")
