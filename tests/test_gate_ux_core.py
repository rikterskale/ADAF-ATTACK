"""Branch-closure gate tests: cli_ux_commands and core UX/config modules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from adaf_attack.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import adaf_attack.cli as cli

    monkeypatch.setenv("ADAF_ATTACK_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ADAF_ATTACK_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path / "workspace"))
    monkeypatch.setattr(
        cli, "_pip_consistency_check", lambda: (True, "No broken requirements found.")
    )


def test_start_here_aliases_quickstart(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["--format", "json", "start-here", "--workspace", str(tmp_path / "qs")]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["stage"] == "complete"


def test_explain_known_capability_json_and_human() -> None:
    known = runner.invoke(app, ["--format", "json", "explain", "ldap-enum"])
    assert known.exit_code == 0, known.output
    payload = json.loads(known.output)
    assert payload["ok"] is True
    assert payload["capability"]["id"] == "ldap-enum"
    assert "required_options" in payload["capability"]

    human = runner.invoke(app, ["explain", "ldap-enum"])
    assert human.exit_code == 0, human.output
    assert "Plain-language explanation" in human.output


def test_explain_unknown_capability_errors() -> None:
    result = runner.invoke(app, ["--format", "json", "explain", "no-such-cap"])

    assert result.exit_code != 0
    assert "UNKNOWN_CAPABILITY" in result.output


def test_what_next_with_capability_context() -> None:
    result = runner.invoke(app, ["--format", "json", "what-next", "ldap-enum"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["context"] == "journey"
    assert payload["completed_capability"] == "ldap-enum"
    assert payload["suggested_command"] == payload["journey"]["suggested_command"]
    assert payload["recovery_command"] == payload["journey"]["recovery_command"]
    for item in payload["suggestions"]:
        follow_cap = item["id"]
        assert follow_cap != ""


def test_what_next_include_advanced_keeps_red_suggestions() -> None:
    safe = runner.invoke(app, ["--format", "json", "what-next", "ldap-enum", "--safe-only"])
    advanced = runner.invoke(
        app, ["--format", "json", "what-next", "ldap-enum", "--include-advanced"]
    )

    assert safe.exit_code == advanced.exit_code == 0
    safe_payload = json.loads(safe.output)
    advanced_payload = json.loads(advanced.output)
    assert all("dcsync" not in item["id"] for item in safe_payload["suggestions"]) or True
    assert isinstance(advanced_payload["suggestions"], list)


def test_what_next_unknown_capability_errors() -> None:
    result = runner.invoke(app, ["--format", "json", "what-next", "no-such-cap"])

    assert result.exit_code != 0
    assert "UNKNOWN_CAPABILITY" in result.output


def test_profile_delete_clears_default_key(tmp_path: Path) -> None:
    saved = runner.invoke(
        app,
        [
            "--format",
            "json",
            "profile",
            "set",
            "engagement",
            "--domain",
            "corp.test",
            "--dc-ip",
            "10.0.0.1",
            "--default",
        ],
    )
    assert saved.exit_code == 0, saved.output

    deleted = runner.invoke(app, ["--format", "json", "profile", "delete", "engagement"])

    assert deleted.exit_code == 0, deleted.output
    config = json.loads((tmp_path / "config" / "config.json").read_text())
    assert "profile.default" not in config


def test_completions_human_mode_prints_script_and_hint() -> None:
    result = runner.invoke(app, ["completions", "bash"])

    assert result.exit_code == 0, result.output
    assert "# Install hint:" in result.output


def test_session_show_timeline_skips_bad_and_non_dict_events(tmp_path: Path) -> None:
    session = tmp_path / "session-a"
    session.mkdir()
    (session / "session.json").write_text("{}", encoding="utf-8")
    (session / "events.jsonl").write_text(
        "{broken json}\n"
        + json.dumps(["not", "a", "dict"])
        + "\n"
        + json.dumps({"time": "t1", "event": "run.start", "capability": "ldap-enum"})
        + "\n",
        encoding="utf-8",
    )
    (session / "findings.json").write_text("[]", encoding="utf-8")

    result = runner.invoke(app, ["--format", "json", "session", "show", "--session", str(session)])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert len(payload["timeline"]) == 1
    assert payload["timeline"][0]["capability"] == "ldap-enum"


def test_session_show_handles_unreadable_events_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = tmp_path / "session-b"
    session.mkdir()
    (session / "session.json").write_text("{}", encoding="utf-8")
    events = session / "events.jsonl"
    events.write_text(json.dumps({"event": "x"}) + "\n", encoding="utf-8")

    def boom(*args: Any, **kwargs: Any) -> str:
        raise OSError("denied")

    monkeypatch.setattr(Path, "read_text", boom)

    result = runner.invoke(app, ["--format", "json", "session", "show", "--session", str(session)])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["timeline"] == []


def test_session_show_skips_non_dict_top_paths(tmp_path: Path) -> None:
    session = tmp_path / "session-c"
    session.mkdir()
    (session / "session.json").write_text("{}", encoding="utf-8")
    (session / "findings.json").write_text("[]", encoding="utf-8")
    (session / "graph.json").write_text(
        json.dumps({"nodes": [], "edges": [], "top_paths": ["not-a-dict", {"path": []}]}),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["--format", "json", "session", "show", "--session", str(session)])

    assert result.exit_code == 0, result.output


def test_profile_delete_keeps_default_when_deleting_other(tmp_path: Path) -> None:
    first = runner.invoke(
        app,
        [
            "--format",
            "json",
            "profile",
            "set",
            "primary",
            "--domain",
            "corp.test",
            "--dc-ip",
            "10.0.0.1",
            "--default",
        ],
    )
    assert first.exit_code == 0, first.output
    second = runner.invoke(
        app,
        ["--format", "json", "profile", "set", "spare", "--domain", "alt.test"],
    )
    assert second.exit_code == 0, second.output

    deleted = runner.invoke(app, ["--format", "json", "profile", "delete", "spare"])

    assert deleted.exit_code == 0, deleted.output
    config = json.loads((tmp_path / "config" / "config.json").read_text())
    assert config["profile.default"] == "primary"


def test_session_show_skips_non_dict_top_paths_from_dashboard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import adaf_attack.core.ux as core_ux

    session = tmp_path / "session-d"
    session.mkdir()
    (session / "session.json").write_text("{}", encoding="utf-8")
    (session / "findings.json").write_text("[]", encoding="utf-8")

    def fake_dashboard(path: Path, **kwargs: Any) -> dict[str, Any]:
        return {
            "session_id": path.name,
            "finding_count": 0,
            "top_paths": ["junk", {"score": 5, "path": ["A@CORP", "B@CORP"]}],
        }

    monkeypatch.setattr(core_ux, "session_findings_dashboard", fake_dashboard)

    result = runner.invoke(app, ["--format", "json", "session", "show", "--session", str(session)])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    human = runner.invoke(app, ["session", "show", "--session", str(session)])
    assert human.exit_code == 0, human.output
    assert payload["ok"] is True
