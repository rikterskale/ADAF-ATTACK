"""Behavioral tests."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

import adaf_attack.cli as cli
from adaf_attack.cli import app
from adaf_attack.core.runner import RunError

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path / "workspace"))


class _TtyStdout:
    def __init__(self, real: Any) -> None:
        self._real = real

    def isatty(self) -> bool:
        return True

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


class _SysProxy:
    def __init__(self, real: Any) -> None:
        self._real = real

    def __getattr__(self, name: str) -> Any:
        if name == "stdout":
            return _TtyStdout(self._real.stdout)
        return getattr(self._real, name)


def _json_ctx() -> Any:
    return SimpleNamespace(ensure_object=lambda _: {"output_format": "json"})


# --------------------------- pure helpers ---------------------------


def test_summary_lines_capability_and_next_steps() -> None:
    payload = {
        "ok": True,
        "count": 1,
        "capability": {"id": "c1", "summary": "Does things"},
        "next_steps": ["step one", "step two"],
    }
    text = "\n".join(cli._summary_lines(payload))
    assert "capability: c1" in text
    assert "summary: Does things" in text
    assert "- step one" in text


def test_beginner_lines_actions_finding_and_fallback() -> None:
    actions = cli._beginner_lines(
        {"actions": [{"goal": "g", "command": "c"}, "junk", {"goal": "g2", "command": "c2"}]}
    )
    assert actions == ["g: c", "g2: c2"]

    finding = cli._beginner_lines(
        {
            "finding": {
                "title": "T",
                "severity": "high",
                "why_it_matters": "because",
                "recommended_next_step": "do this",
            }
        }
    )
    assert finding[0] == "T is rated high."
    assert "Next: do this" in finding

    fallback = cli._beginner_lines({"ok": True})
    assert fallback[0] == "ok: True"


def test_replace_support_identifiers_skips_empty_identifier() -> None:
    assert cli._replace_support_identifiers("corp", ("",)) == "corp"


def test_require_destructive_ack_appends_and_persists(tmp_path: Path) -> None:
    cli._require_destructive_ack(_json_ctx(), "cap-x", tmp_path, explicit=True, interactive=False)
    marker = tmp_path / ".adaf-attack-destructive-ack.json"
    data = json.loads(marker.read_text(encoding="utf-8"))
    assert data["capabilities"] == ["cap-x"]


def test_require_destructive_ack_write_failure_json_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self: Any, *a: Any, **k: Any) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(Path, "write_text", boom)
    cli._require_destructive_ack(_json_ctx(), "cap-y", tmp_path, explicit=True, interactive=False)


# --------------------------- doctor / check ---------------------------


def test_doctor_first_run_quickstart_lines(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path / "fresh-ws"))

    result = runner.invoke(app, ["--format", "json", "doctor"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["first_run"] is True


def test_doctor_downgrades_path_errors_for_offline_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "_path_write_probe", lambda path: (False, "OSError: denied"))

    result = runner.invoke(app, ["--format", "json", "doctor", "--profile", "offline"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    path_checks = [
        c for c in payload["checks"] if c["id"] in {"data_dir", "config_dir", "workspace"}
    ]
    assert path_checks
    for check in path_checks:
        assert check["status"] == "warning"
        assert check["severity"] == "advisory"


def test_check_requires_domain_and_dc_ip_together() -> None:
    result = runner.invoke(app, ["check", "--domain", "corp.test"])

    assert result.exit_code != 0
    assert "both --domain and --dc-ip" in result.output


# --------------------------- favorites ---------------------------


def test_favorites_add_unknown_capability() -> None:
    result = runner.invoke(app, ["--format", "json", "favorites", "add", "no-such-cap"])

    assert result.exit_code == 1
    assert "UNKNOWN_CAPABILITY" in result.output


def test_favorites_remove_unpins(tmp_path: Path) -> None:
    result = runner.invoke(app, ["--format", "json", "favorites", "remove", "ldap-enum"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert "ldap-enum" not in payload["favorites"]


# --------------------------- sessions ---------------------------


def _make_ws(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    new = ws / "s_new"
    new.mkdir()
    (new / "session.json").write_text(
        json.dumps({"session_id": "s_new", "created_at": datetime.now(UTC).isoformat()}),
        encoding="utf-8",
    )
    old = ws / "s_old"
    old.mkdir()
    (old / "session.json").write_text(
        json.dumps({"session_id": "s_old", "created_at": "2020-01-01T00:00:00+00:00"}),
        encoding="utf-8",
    )
    broken = ws / "s_broken"
    broken.mkdir()
    (broken / "session.json").write_text("{not json", encoding="utf-8")
    (ws / "not_a_session").mkdir()
    return ws


def test_sessions_filters_by_since_limit_and_session(tmp_path: Path) -> None:
    ws = _make_ws(tmp_path)

    result = runner.invoke(
        app, ["--format", "json", "sessions", "--workspace", str(ws), "--since", "24h"]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    ids = {entry["session_id"] for entry in payload["sessions"]}
    assert "s_new" in ids
    assert "s_old" not in ids

    single = runner.invoke(
        app,
        [
            "--format",
            "json",
            "sessions",
            "--workspace",
            str(ws),
            "--session",
            "s_new",
            "--limit",
            "1",
        ],
    )
    assert single.exit_code == 0, single.output
    single_payload = json.loads(single.output)
    assert [entry["session_id"] for entry in single_payload["sessions"]] == ["s_new"]


def test_sessions_missing_workspace_root(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["--format", "json", "sessions", "--workspace", str(tmp_path / "missing")]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["sessions"] == []


def test_session_resume_builds_package(tmp_path: Path) -> None:
    session = tmp_path / "sess"
    session.mkdir()
    (session / "session.json").write_text(json.dumps({"session_id": "sess"}), encoding="utf-8")
    events = "\n".join(
        [
            json.dumps({"capability": "ldap-enum"}),
            "{broken json",
            json.dumps({"level": "info"}),
            json.dumps({"capability": "ldap-enum"}),
            json.dumps({"capability": "bloodhound-export"}),
        ]
    )
    (session / "events.jsonl").write_text(events, encoding="utf-8")

    result = runner.invoke(
        app, ["--format", "json", "session", "resume", "--session", str(session)]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["capabilities_seen"] == ["ldap-enum", "bloodhound-export"]
    assert payload["execution"] == "not-started"


def test_session_resume_missing_session(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["--format", "json", "session", "resume", "--session", str(tmp_path / "nope")]
    )

    assert result.exit_code == 1
    assert "SESSION_NOT_FOUND" in result.output


# --------------------------- engagement package preview ---------------------------


def test_engagement_package_preview_redacts_and_excludes(tmp_path: Path) -> None:
    session = tmp_path / "sess"
    session.mkdir()
    (session / "findings.json").write_text(
        json.dumps({"findings": [{"id": "F1", "password": "hunter2"}]}), encoding="utf-8"
    )
    (session / "notes.txt").write_text("plain notes", encoding="utf-8")
    (session / "secret.pem").write_text("key material", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "engagement",
            "package",
            "--session",
            str(session),
            "--output",
            str(tmp_path / "pkg.zip"),
            "--preview",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "secret.pem" in payload["excluded_files"]
    assert "notes.txt" not in payload["excluded_files"]
    assert "findings.json" not in payload["excluded_files"]


# --------------------------- rank-paths exploit chains ---------------------------


def test_rank_paths_prints_exploit_chains_without_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class _ChainGraph:
        def summary(self) -> dict[str, int]:
            return {"nodes": 2, "edges": 1}

        def rank_from_principals(self, starts: Any, **k: Any) -> list[Any]:
            return []

        def rank_exploit_chains(self, starts: Any, **k: Any) -> list[Any]:
            return [
                {
                    "score": 4.5,
                    "terminal_relation": "Owns",
                    "impact": "domain admin",
                    "confidence": "high",
                }
            ]

    graph = tmp_path / "g.json"
    graph.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cli.AttackGraph, "from_file", staticmethod(lambda p: _ChainGraph()))

    result = runner.invoke(app, ["rank-paths", "--graph", str(graph)])

    assert result.exit_code == 0, result.output
    assert "Exploit chains" in result.output
    assert "domain admin" in result.output


# --------------------------- run command branches ---------------------------


def test_run_uses_cli_username_skipping_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, Any] = {}

    def fake_exec(capability: str, target: Any, **kwargs: Any) -> dict[str, Any]:
        seen["username"] = getattr(target, "username", None)
        return {"session_path": str(tmp_path), "ok": True}

    monkeypatch.setattr(cli, "execute_capability", fake_exec)

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
            "10.0.0.1",
            "--username",
            "admin",
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen["username"] == "admin"


def test_run_destructive_confirmation_declined(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "sys", _SysProxy(sys))

    result = runner.invoke(
        app,
        ["run", "shadow-creds", "--domain", "corp.test", "--dc-ip", "10.0.0.1", "--force"],
        input="n\n",
    )

    assert result.exit_code != 0
    assert "USER_ABORTED" in result.output


def test_spinner_stage_hint_recovers_from_registry_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import adaf_attack.capabilities  # noqa: F401
    from adaf_attack.core.registry import capability_registry

    original_get = capability_registry.get
    state = {"calls": 0}

    def flaky_get(capability_id: str) -> Any:
        state["calls"] += 1
        if state["calls"] > 1:
            raise RuntimeError("registry exploded")
        return original_get(capability_id)

    monkeypatch.setattr(capability_registry, "get", flaky_get)
    monkeypatch.setattr(
        cli, "execute_capability", lambda *a, **k: {"session_path": str(tmp_path), "ok": True}
    )
    monkeypatch.setattr(cli, "sys", _SysProxy(sys))

    result = runner.invoke(
        app,
        ["run", "ldap-enum", "--domain", "corp.test", "--dc-ip", "10.0.0.1"],
    )

    assert result.exit_code == 0, result.output
    assert f"Session: {tmp_path}" in result.output


def test_spinner_handles_unknown_capability_hint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from adaf_attack.core.registry import capability_registry

    monkeypatch.setattr(capability_registry, "get", lambda capability_id: None)
    monkeypatch.setattr(
        cli, "execute_capability", lambda *a, **k: {"session_path": str(tmp_path), "ok": True}
    )
    monkeypatch.setattr(cli, "sys", _SysProxy(sys))

    result = runner.invoke(
        app,
        ["run", "mystery-cap", "--domain", "corp.test", "--dc-ip", "10.0.0.1"],
    )

    assert result.exit_code == 0, result.output


# --------------------------- interactive prompts ---------------------------


def _interactive(
    monkeypatch: pytest.MonkeyPatch,
    prompts: list[dict[str, Any]],
    answers: list[str],
    *,
    provided: dict[str, Any] | None = None,
    confirm: bool = True,
) -> dict[str, Any]:
    import adaf_attack.core.novice as novice

    monkeypatch.setattr(novice, "required_prompts", lambda cap: prompts)
    answers_iter = iter(answers)
    monkeypatch.setattr(cli.typer, "prompt", lambda *a, **k: next(answers_iter))
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: confirm)
    return cli._interactive_run_prompts(
        _json_ctx(), "ldap-enum", provided=provided or {}, force_already=False
    )


def test_interactive_param_prompt_blank_answer_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collected = _interactive(
        monkeypatch,
        [
            {
                "option": "-P",
                "is_param": True,
                "param_key": "ldap_filter",
                "label": "LDAP filter",
                "help": "helpful text",
            }
        ],
        [""],
    )
    assert "__extra_params__" not in collected


def test_interactive_extra_param_with_empty_key_is_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collected = _interactive(
        monkeypatch,
        [
            {
                "option": "-P",
                "is_param": True,
                "param_key": "",
                "label": "Param",
                "help": "helpful text",
            }
        ],
        ["value"],
    )
    assert collected["__extra_params__"] == ["=value"]


# --------------------------- capability-help (`command`) ---------------------------


def test_command_unknown_capability_exits_with_error() -> None:
    result = runner.invoke(app, ["--format", "json", "command", "definitely-not-real"])

    assert result.exit_code == 1
    assert "UNKNOWN_CAPABILITY" in result.output


# --------------------------- findings ---------------------------


_FINDING = {
    "id": "F1",
    "finding_id": "F1",
    "title": "Weak thing",
    "severity": "high",
    "why_it_matters": "it matters",
    "recommended_next_step": "fix it",
}


def _finding_session(tmp_path: Path, document: str, name: str = "sess") -> Path:
    session = tmp_path / name
    session.mkdir()
    (session / "findings.json").write_text(document, encoding="utf-8")
    (session / "session.json").write_text("{}", encoding="utf-8")
    return session


def test_load_session_finding_rejects_non_list_findings(tmp_path: Path) -> None:
    session = _finding_session(tmp_path, json.dumps({"findings": {"a": 1}}))

    with pytest.raises(Exception) as excinfo:
        cli._load_session_finding(session, "F1")
    assert "UNKNOWN_FINDING" in str(excinfo.value)


def test_load_session_finding_skips_non_dict_entries(tmp_path: Path) -> None:
    session = _finding_session(tmp_path, json.dumps(["junk", _FINDING]))

    found = cli._load_session_finding(session, "F1")
    assert found["id"] == "F1"

    session2 = _finding_session(tmp_path, json.dumps(["junk"]), name="sess2")
    with pytest.raises(Exception) as excinfo:
        cli._load_session_finding(session2, "F1")
    assert "UNKNOWN_FINDING" in str(excinfo.value)


def test_finding_explain_missing_session(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "finding",
            "explain",
            "--session",
            str(tmp_path / "missing"),
            "--id",
            "F1",
        ],
    )

    assert result.exit_code == 1
    assert "SESSION_NOT_FOUND" in result.output


def test_finding_remediate_corrupt_findings_file(tmp_path: Path) -> None:
    session = _finding_session(tmp_path, "{broken")

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "finding",
            "remediate",
            "--session",
            str(session),
            "--id",
            "F1",
        ],
    )

    assert result.exit_code == 1
    assert "SESSION_NOT_FOUND" in result.output


def test_finding_triage_unknown_finding(tmp_path: Path) -> None:
    session = _finding_session(tmp_path, json.dumps({"findings": [_FINDING]}))

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "finding",
            "triage",
            "--session",
            str(session),
            "--id",
            "missing-id",
        ],
    )

    assert result.exit_code == 1
    assert "UNKNOWN_FINDING" in result.output


def test_finding_triage_invalid_status(tmp_path: Path) -> None:
    session = _finding_session(tmp_path, json.dumps({"findings": [_FINDING]}))

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "finding",
            "triage",
            "--session",
            str(session),
            "--id",
            "F1",
            "--status",
            "bogus",
        ],
    )

    assert result.exit_code == 1
    assert "INVALID_FINDING_STATUS" in result.output


def test_finding_triage_updates_all_fields_then_duplicate_tag(tmp_path: Path) -> None:
    session = _finding_session(tmp_path, json.dumps({"findings": [_FINDING]}))

    first = runner.invoke(
        app,
        [
            "--format",
            "json",
            "finding",
            "triage",
            "--session",
            str(session),
            "--id",
            "F1",
            "--status",
            "acknowledged",
            "--tag",
            "new-tag",
            "--note",
            "looks bad",
            "--owner",
            "alice",
            "--comment",
            "pending review",
        ],
    )

    assert first.exit_code == 0, first.output
    payload = json.loads(first.output)
    assert payload["updated"] is True
    assert payload["finding"]["status"] == "acknowledged"
    assert payload["finding"]["tags"] == ["new-tag"]
    assert payload["finding"]["owner"] == "alice"

    duplicate = runner.invoke(
        app,
        [
            "--format",
            "json",
            "finding",
            "triage",
            "--session",
            str(session),
            "--id",
            "F1",
            "--tag",
            "new-tag",
        ],
    )

    assert duplicate.exit_code == 0, duplicate.output
    dup_payload = json.loads(duplicate.output)
    assert dup_payload["finding"]["tags"] == ["new-tag"]


def test_finding_triage_view_only_skips_write(tmp_path: Path) -> None:
    session = _finding_session(tmp_path, json.dumps({"findings": [_FINDING]}))
    before = (session / "findings.json").read_text(encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "finding",
            "triage",
            "--session",
            str(session),
            "--id",
            "F1",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["updated"] is False
    assert (session / "findings.json").read_text(encoding="utf-8") == before


def test_finding_triage_write_fails_when_document_is_not_a_mapping(tmp_path: Path) -> None:
    session = _finding_session(tmp_path, json.dumps([_FINDING]))

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "finding",
            "triage",
            "--session",
            str(session),
            "--id",
            "F1",
            "--status",
            "open",
        ],
    )

    assert result.exit_code == 1
    assert "FINDING_TRIAGE_WRITE_FAILED" in result.output


def test_finding_triage_write_fails_when_finding_vanishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _finding_session(tmp_path, json.dumps({"findings": [_FINDING]}))
    monkeypatch.setattr(cli, "_load_session_finding", lambda s, f: {"id": "ghost"})

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "finding",
            "triage",
            "--session",
            str(session),
            "--id",
            "ghost",
            "--status",
            "open",
        ],
    )

    assert result.exit_code == 1
    assert "FINDING_TRIAGE_WRITE_FAILED" in result.output


# --------------------------- init ---------------------------


def test_init_prompt_blank_answer_saves_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.typer, "prompt", lambda *a, **k: "")

    result = runner.invoke(app, ["init", "--skip-quickstart"])

    assert result.exit_code == 0, result.output
    assert "No defaults saved." in result.output


# --------------------------- residual gate gaps ---------------------------


def test_require_destructive_ack_write_failure_human_mode_warns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self: Any, *a: Any, **k: Any) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(Path, "write_text", boom)
    human_ctx = SimpleNamespace(ensure_object=lambda _: {})

    cli._require_destructive_ack(human_ctx, "cap-z", tmp_path, explicit=True, interactive=False)


def test_summary_lines_capability_dict_without_summary() -> None:
    lines = cli._summary_lines(
        {"ok": True, "capability": {"id": "cap-x"}, "next_steps": ["step one"]}
    )

    assert any("capability: cap-x" in line for line in lines)
    assert not any("summary:" in line for line in lines)


def test_doctor_first_run_human_mode_prints_quickstart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path / "fresh-ws"))

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0, result.output
    assert "First run - quickstart:" in result.output


def test_check_preflight_delegates_to_doctor(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_doctor(ctx: Any, **kwargs: Any) -> None:
        seen.update(kwargs)

    monkeypatch.setattr(cli, "doctor", fake_doctor)

    result = runner.invoke(
        app,
        ["check", "--domain", "corp.test", "--dc-ip", "10.0.0.1"],
    )

    assert result.exit_code == 0, result.output
    assert seen["profile"] == "live-ad"
    assert seen["domain"] == "corp.test"


def test_run_destructive_yes_skips_confirmation_prompt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cli, "sys", _SysProxy(sys))
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path / "ws"))
    monkeypatch.setattr(
        cli,
        "execute_capability",
        lambda *a, **k: {"session_path": str(tmp_path), "ok": True},
    )

    result = runner.invoke(
        app,
        [
            "run",
            "shadow-creds",
            "--domain",
            "corp.test",
            "--dc-ip",
            "10.0.0.1",
            "--force",
            "--yes",
        ],
        input="shadow-creds\n",
    )

    assert result.exit_code == 0, result.output
    assert "DESTRUCTIVE" not in result.output


def test_run_generic_run_error_maps_to_classified_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*a: Any, **k: Any) -> dict[str, Any]:
        raise RunError("ldap server unreachable")

    monkeypatch.setattr(cli, "execute_capability", boom)

    result = runner.invoke(
        app,
        ["--format", "json", "run", "ldap-enum", "--domain", "corp.test", "--dc-ip", "10.0.0.1"],
    )

    assert result.exit_code != 0
    assert "ldap server unreachable" in result.output


def test_session_resume_skips_malformed_and_non_capability_events(
    tmp_path: Path,
) -> None:
    session = tmp_path / "session-a"
    session.mkdir()
    (session / "session.json").write_text("{}", encoding="utf-8")
    (session / "events.jsonl").write_text(
        "{not json}\n"
        + json.dumps({"kind": "note"})
        + "\n"
        + json.dumps({"capability": "ldap-enum"})
        + "\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app, ["--format", "json", "session", "resume", "--session", str(session)]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["capabilities_seen"] == ["ldap-enum"]


def test_require_destructive_ack_skips_duplicate_capability(tmp_path: Path) -> None:
    cli._require_destructive_ack(_json_ctx(), "cap-dup", tmp_path, explicit=True, interactive=False)
    cli._require_destructive_ack(_json_ctx(), "cap-dup", tmp_path, explicit=True, interactive=False)

    marker = tmp_path / ".adaf-attack-destructive-ack.json"
    data = json.loads(marker.read_text(encoding="utf-8"))
    assert data["capabilities"] == ["cap-dup"]


def test_doctor_first_run_multiline_quickstart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path / "fresh-ws"))
    real_payload = cli._doctor_payload

    def with_multiline_next_step(profile: str, **kwargs: Any) -> dict[str, Any]:
        payload = real_payload(profile, **kwargs)
        if payload["first_run"]:
            payload["next_step"] = "Header line\nstep one\nstep two"
        return payload

    monkeypatch.setattr(cli, "_doctor_payload", with_multiline_next_step)

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0, result.output
    assert "step one" in result.output
    assert "Header line" not in result.output


def test_run_destructive_confirmation_accepted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cli, "sys", _SysProxy(sys))
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path / "ws"))
    monkeypatch.setattr(
        cli,
        "execute_capability",
        lambda *a, **k: {"session_path": str(tmp_path), "ok": True},
    )

    result = runner.invoke(
        app,
        ["run", "shadow-creds", "--domain", "corp.test", "--dc-ip", "10.0.0.1", "--force"],
        input="y\nshadow-creds\n",
    )

    assert result.exit_code == 0, result.output


def test_session_resume_deduplicates_capability_events(tmp_path: Path) -> None:
    session = tmp_path / "session-a"
    session.mkdir()
    (session / "session.json").write_text("{}", encoding="utf-8")
    (session / "events.jsonl").write_text(
        json.dumps({"capability": "ldap-enum"})
        + "\n"
        + json.dumps({"capability": "ldap-enum"})
        + "\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app, ["--format", "json", "session", "resume", "--session", str(session)]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["capabilities_seen"] == ["ldap-enum"]


def test_session_resume_without_events_file(tmp_path: Path) -> None:
    session = tmp_path / "session-bare"
    session.mkdir()
    (session / "session.json").write_text("{}", encoding="utf-8")

    result = runner.invoke(
        app, ["--format", "json", "session", "resume", "--session", str(session)]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["capabilities_seen"] == []
