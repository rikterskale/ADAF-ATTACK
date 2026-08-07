"""Tests for the 15 UX enhancements added on top of test_cli_contract."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from adaf_attack.cli import app
from adaf_attack.core import user_config

runner = CliRunner()


def test_errors_command_lists_catalog() -> None:
    result = runner.invoke(app, ["--format", "json", "errors"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    codes = {entry["code"] for entry in payload["errors"]}
    assert {"UNKNOWN_CAPABILITY", "DESTRUCTIVE_CONFIRMATION_REQUIRED", "USER_ABORTED"} <= codes


def test_errors_single_code_shows_detail() -> None:
    result = runner.invoke(app, ["--format", "json", "errors", "UNKNOWN_CAPABILITY"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["count"] == 1
    assert payload["errors"][0]["code"] == "UNKNOWN_CAPABILITY"


def test_paths_reports_existence_and_writability(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path / "ws"))

    result = runner.invoke(app, ["--format", "json", "paths"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    names = {entry["name"] for entry in payload["entries"]}
    assert {"data", "config", "workspace"} <= names
    for entry in payload["entries"]:
        assert isinstance(entry["exists"], bool)
        assert isinstance(entry["writable"], bool)


def test_sessions_shows_bytes_human_and_supports_limit(tmp_path: Path) -> None:
    for i in range(3):
        session = tmp_path / f"session-{i}"
        session.mkdir()
        (session / "session.json").write_text(
            json.dumps({"session_id": f"session-{i}", "created_at": "2026-08-01T00:00:00+00:00"}),
            encoding="utf-8",
        )
    result = runner.invoke(
        app, ["--format", "json", "sessions", "--workspace", str(tmp_path), "--limit", "2"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["cleanup"]["session_count"] == 2
    assert "bytes_human" in payload["cleanup"]


def test_capability_help_lists_required_options() -> None:
    result = runner.invoke(app, ["--format", "json", "capability-help", "shadow-creds"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    cap = payload["capability"]
    assert "--sam" in cap["required_options"]
    assert "--force" in cap["required_options"]
    assert cap["notes"]


def test_config_set_show_unset_roundtrip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(user_config, "config_path", lambda: tmp_path / "config.json")

    set_result = runner.invoke(
        app, ["--format", "json", "config", "set", "target.domain", "corp.example"]
    )
    assert set_result.exit_code == 0, set_result.output
    show_result = runner.invoke(app, ["--format", "json", "config", "show"])
    show_payload = json.loads(show_result.output)
    assert show_payload["config"]["target.domain"] == "corp.example"

    unset_result = runner.invoke(app, ["--format", "json", "config", "unset", "target.domain"])
    assert unset_result.exit_code == 0
    show_result_2 = runner.invoke(app, ["--format", "json", "config", "show"])
    assert "target.domain" not in json.loads(show_result_2.output)["config"]


def test_config_set_rejects_unknown_key(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(user_config, "config_path", lambda: tmp_path / "config.json")

    result = runner.invoke(app, ["--format", "json", "config", "set", "not.a.key", "x"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["error"]["code"] == "CONFIG_KEY_INVALID"


def test_run_payload_missing_file_errors() -> None:
    result = runner.invoke(
        app,
        [
            "run",
            "gpo-abuse",
            "--domain",
            "corp.example",
            "--dc-ip",
            "10.0.0.10",
            "--payload",
            "@/does/not/exist.xml",
            "--force",
            "--yes",
        ],
    )
    assert result.exit_code != 0
    assert "does not exist" in result.output.lower()


def test_run_dry_run_does_not_execute() -> None:
    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "run",
            "ldap-enum",
            "--domain",
            "corp.example",
            "--dc-ip",
            "10.0.0.10",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["mode"] == "preview"


def test_capability_subgroup_list_alias_works() -> None:
    result = runner.invoke(app, ["--format", "json", "capability", "list"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["count"] > 0


def test_session_subgroup_list_alias_works(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["--format", "json", "session", "list", "--workspace", str(tmp_path)]
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["cleanup"]["session_count"] == 0


def test_doctor_first_run_hint_present(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path / "ws"))
    result = runner.invoke(app, ["--format", "json", "doctor"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["first_run"] is True
    assert "engagement init" in payload["next_step"]
