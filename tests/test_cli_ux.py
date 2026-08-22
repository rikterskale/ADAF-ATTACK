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


def test_errors_catalog_covers_all_emitted_user_facing_codes() -> None:
    from adaf_attack.core.cli_contract import ERROR_CATALOG

    emitted_codes = {
        "FIRST_DESTRUCTIVE_USE_CONFIRMATION_REQUIRED",
        "INVALID_PROFILE",
        "QUICKSTART_WORKSPACE_EXISTS",
        "QUICKSTART_WRITE_FAILED",
        "UNKNOWN_ERROR_CODE",
    }
    assert emitted_codes <= ERROR_CATALOG.keys()


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


def test_paths_repair_creates_application_directories(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ADAF_ATTACK_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path / "workspace"))

    result = runner.invoke(app, ["--format", "json", "paths", "--repair"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert all(item["status"] == "created-or-present" for item in payload["repair"])
    assert (tmp_path / "data").is_dir()
    assert (tmp_path / "config").is_dir()
    assert (tmp_path / "workspace").is_dir()


def test_paths_repair_reports_permission_failure(monkeypatch) -> None:
    def deny_mkdir(self, *args, **kwargs):
        raise PermissionError("locked")

    monkeypatch.setattr(Path, "mkdir", deny_mkdir)
    result = runner.invoke(app, ["--format", "json", "paths", "--repair"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is False
    assert all(item["status"].startswith("error:") for item in payload["repair"])


def test_quickstart_runs_safe_offline_acceptance(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ADAF_ATTACK_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path / "workspace"))

    result = runner.invoke(
        app, ["--format", "json", "quickstart", "--workspace", str(tmp_path / "quickstart")]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["stage"] == "complete"
    assert Path(payload["session_path"]).joinpath("session.json").is_file()


def test_quickstart_does_not_overwrite_existing_session(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ADAF_ATTACK_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path / "workspace"))
    destination = tmp_path / "quickstart" / "demo-session"
    destination.mkdir(parents=True)
    marker = destination / "preserve-me.txt"
    marker.write_text("keep", encoding="utf-8")

    result = runner.invoke(
        app, ["--format", "json", "quickstart", "--workspace", str(tmp_path / "quickstart")]
    )

    assert result.exit_code != 0
    assert json.loads(result.output)["error"]["code"] == "QUICKSTART_WORKSPACE_EXISTS"
    assert marker.read_text(encoding="utf-8") == "keep"


def test_quickstart_stops_when_doctor_fails(tmp_path: Path, monkeypatch) -> None:
    import adaf_attack.cli as cli

    monkeypatch.setattr(
        cli,
        "_doctor_payload",
        lambda *args, **kwargs: {"ok": False, "checks": [], "next_step": "repair paths"},
    )
    result = runner.invoke(app, ["--format", "json", "quickstart", "--workspace", str(tmp_path)])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["stage"] == "doctor"


def test_quickstart_reports_demo_write_failure(tmp_path: Path, monkeypatch) -> None:
    import adaf_attack.demo as demo

    def fail_materialize(destination: Path) -> Path:
        raise OSError("locked")

    monkeypatch.setattr(demo, "materialize_demo_session", fail_materialize)
    result = runner.invoke(app, ["--format", "json", "quickstart", "--workspace", str(tmp_path)])

    assert result.exit_code == 1
    assert json.loads(result.output)["error"]["code"] == "QUICKSTART_WRITE_FAILED"


def test_config_set_permission_error_is_actionable(monkeypatch) -> None:
    import adaf_attack.core.user_config as user_config

    def fail(*args, **kwargs):
        raise PermissionError("profile is locked")

    monkeypatch.setattr(user_config, "set_key", fail)
    result = runner.invoke(app, ["--format", "json", "config", "set", "workspace", "./lab"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["error"]["code"] == "CONFIG_WRITE_FAILED"
    assert "doctor --explain" in payload["error"]["remediation"]


def test_config_unset_permission_error_is_actionable(monkeypatch) -> None:
    import adaf_attack.core.user_config as user_config

    def fail(*args, **kwargs):
        raise PermissionError("profile is locked")

    monkeypatch.setattr(user_config, "unset_key", fail)
    result = runner.invoke(app, ["--format", "json", "config", "unset", "workspace"])
    assert result.exit_code == 1
    assert json.loads(result.output)["error"]["code"] == "CONFIG_WRITE_FAILED"


def test_capability_help_survives_read_only_preferences(monkeypatch) -> None:
    import adaf_attack.core.user_config as user_config

    monkeypatch.setattr(
        user_config,
        "save_user_config",
        lambda data: (_ for _ in ()).throw(PermissionError("profile is locked")),
    )
    result = runner.invoke(app, ["capability-help", "ldap-enum"])
    assert result.exit_code == 0, result.output
    assert "ldap-enum" in result.output


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
    monkeypatch.setattr("adaf_attack.cli._python_supported", lambda: True)
    monkeypatch.setenv("ADAF_ATTACK_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ADAF_ATTACK_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path / "ws"))
    result = runner.invoke(app, ["--format", "json", "doctor"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["first_run"] is True
    assert "engagement init" in payload["next_step"]


def test_recent_capabilities_are_local_and_ordered(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(user_config, "config_path", lambda: tmp_path / "config.json")

    first = runner.invoke(app, ["capability-help", "ldap-enum"])
    second = runner.invoke(app, ["capability-help", "kerberoast"])
    recent = runner.invoke(app, ["--format", "json", "recent"])

    assert first.exit_code == second.exit_code == recent.exit_code == 0
    payload = json.loads(recent.output)
    assert [item["id"] for item in payload["capabilities"][:2]] == [
        "kerberoast",
        "ldap-enum",
    ]


def test_what_next_without_context_is_dependency_light() -> None:
    result = runner.invoke(app, ["--format", "json", "what-next"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["context"] == "new-user"
    assert payload["suggestions"]


def test_debug_flag_enables_diagnostic_logging() -> None:
    import logging

    result = runner.invoke(app, ["--debug", "--format", "json", "paths"])
    assert result.exit_code == 0, result.output
    # The global --debug flag lowers the package logger to DEBUG so operators
    # can troubleshoot a live run; without it the logger stays quiet.
    assert logging.getLogger("adaf_attack").level == logging.DEBUG

    result = runner.invoke(app, ["--format", "json", "paths"])
    assert result.exit_code == 0, result.output
    assert logging.getLogger("adaf_attack").level == logging.WARNING
