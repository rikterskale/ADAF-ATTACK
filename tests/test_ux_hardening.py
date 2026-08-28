"""Regression coverage for UX hardening and installation-facing behavior."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from adaf_attack.cli import app
from adaf_attack.core import command_templates, user_config
from adaf_attack.core.command_templates import build_exploit_commands
from adaf_attack.core.registry import Capability, capability_registry
from adaf_attack.core.standout_ux import session_timeline
from adaf_attack.core.target import Target
from adaf_attack.core.ux import build_ready_argv, build_ready_command, unified_search
from adaf_attack.tui.app import ADAFAttackApp

runner = CliRunner()


def test_copy_ready_command_quotes_shell_sensitive_values() -> None:
    command = build_ready_command(
        "ldap-enum",
        domain="corp example",
        dc_ip="dc01.example;touch /tmp/should-not-run",
        username="operator one",
        extra={"computer_filter": "(sAMAccountName=DC 01$)"},
    )

    assert "'corp example'" in command
    assert "'dc01.example;touch /tmp/should-not-run'" in command
    assert "'operator one'" in command
    assert "'computer_filter=(sAMAccountName=DC 01$)'" in command


def test_copy_ready_command_uses_native_powershell_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(command_templates, "_WINDOWS_SHELL", True)
    argv = build_ready_argv(
        "ldap-enum",
        domain="O'Brien Corp",
        dc_ip="dc01.example; Write-Output unsafe",
        username="operator one",
    )
    command = build_ready_command(
        "ldap-enum",
        domain="O'Brien Corp",
        dc_ip="dc01.example; Write-Output unsafe",
        username="operator one",
    )
    assert argv[argv.index("--domain") + 1] == "O'Brien Corp"
    assert "--domain 'O''Brien Corp'" in command
    assert "--dc-ip 'dc01.example; Write-Output unsafe'" in command
    assert "--username 'operator one'" in command


def test_ready_command_includes_required_param_placeholders() -> None:
    unpac = build_ready_command("unpac-the-hash", domain="corp.test", dc_ip="10.0.0.1")
    assert "-P" in unpac and "sam=" in unpac and "pfx=" in unpac

    rbcd = build_ready_command(
        "rbcd-ticket-workflow", domain="corp.test", dc_ip="10.0.0.1", force=True
    )
    assert "--set-on" in rbcd and "--set-from" in rbcd and "--impersonate" in rbcd
    assert "--force" in rbcd

    golden = build_ready_command("golden-cert", domain="corp.test", dc_ip="10.0.0.1", force=True)
    assert "ca_pfx=" in golden and "upn=" in golden

    # Explicit extras suppress matching placeholders.
    filled = build_ready_command(
        "unpac-the-hash",
        domain="corp.test",
        dc_ip="10.0.0.1",
        extra={"sam": "alice", "pfx": "alice.pfx"},
    )
    assert filled.count("sam=") == 1 and "alice" in filled


def test_specialized_stages_and_outcome_handoff(tmp_path: Path) -> None:
    import adaf_attack.capabilities  # noqa: F401
    from adaf_attack.core.graph import AttackGraph
    from adaf_attack.core.novice import glossary_items
    from adaf_attack.core.outcomes import build_post_execution_outcome
    from adaf_attack.core.registry import capability_registry
    from adaf_attack.core.ux import stages_for_capability
    from adaf_attack.core.ux_extra import capability_prerequisites

    unpac = capability_registry.get("unpac-the-hash")
    assert unpac is not None
    stages = stages_for_capability(unpac)
    assert stages[0] == "prepare" and "u2u-pac" in stages

    session = tmp_path / "sess"
    session.mkdir()
    (session / "unpac.json").write_text("{}", encoding="utf-8")
    outcome = build_post_execution_outcome(
        session,
        capability="rbcd-ticket-workflow",
        result={
            "ok": False,
            "handoff_complete": True,
            "playbook": str(session / "rbcd-s4u.playbook.txt"),
            "method": "playbook",
        },
        graph=AttackGraph(),
        auth="password",
    )
    assert outcome["status"] == "handoff"
    assert outcome["playbook"].endswith("rbcd-s4u.playbook.txt")
    assert "next_command" in outcome

    glossary = glossary_items()
    assert "unpac" in glossary and "dcshadow" in glossary and "pkinit" in glossary
    deps = capability_prerequisites("pkinit-auth")
    assert "unpac-the-hash" in deps["produces_artifacts_for"]


def test_evidence_command_templates_quote_substituted_values() -> None:
    target = Target(domain="corp example", dc_ip="10.0.0.10", username="operator one")
    commands = build_exploit_commands(
        {"terminal_relation": "HasSPN", "start": "USER@alice", "end": "USER@alice"},
        target,
    )

    assert commands
    assert "-d 'corp example'" in commands[0]["command"]
    assert "-u 'operator one'" in commands[0]["command"]


def test_search_ranks_exact_match_before_applying_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    candidates = [
        Capability("ldap-enum", "Enumerate LDAP", False, "discovery"),
        Capability("ldap-enum-extended", "Extended LDAP", False, "discovery"),
    ]
    monkeypatch.setattr(capability_registry, "list", lambda: candidates)

    result = unified_search("ldap-enum", limit=1)

    assert result["count"] == 1
    assert result["results"][0]["id"] == "ldap-enum"


def test_search_handles_missing_or_malformed_session(tmp_path: Path) -> None:
    missing = unified_search("ldap", session=tmp_path / "missing")
    assert missing["count"] >= 0

    malformed = tmp_path / "malformed"
    malformed.mkdir()
    (malformed / "findings.json").write_text("not-json", encoding="utf-8")
    (malformed / "graph.json").write_text("{not-json", encoding="utf-8")
    (malformed / "unicode-findings.json").write_bytes(b"\xff\xfe\xfd")
    (malformed / "evidence-é.json").write_bytes(b"x" * (2 * 1024 * 1024))
    result = unified_search("evidence", session=malformed)
    assert result["results"][0]["id"] == "evidence-é.json"


def test_timeline_is_bounded_rich_and_redacted(tmp_path: Path) -> None:
    session = tmp_path / "session-évidence"
    session.mkdir()
    events = session / "events.jsonl"
    rows = [
        {
            "ts": f"2026-08-22T00:00:{index:02d}Z",
            "type": "run.complete",
            "capability": "ldap-enum",
            "duration_ms": index,
            "correlation_id": f"run-{index}",
            "message": "safe detail",
            "password": "must-not-appear",
        }
        for index in range(1500)
    ]
    events.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")

    result = session_timeline(session, limit=2)

    assert result["count"] == 1500
    assert len(result["events"]) == 2
    assert result["events"][-1]["duration_ms"] == 1499
    assert result["events"][-1]["correlation_id"] == "run-1499"
    assert result["events"][-1]["details"]["message"] == "safe detail"
    assert "password" not in json.dumps(result)

    events.write_bytes(events.read_bytes() + b"\n\xff\xfe")
    assert session_timeline(session, limit=1)["count"] == 1500


def test_recent_preferences_remain_usable_on_read_only_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(user_config, "load_user_config", dict)
    monkeypatch.setattr(
        user_config, "save_user_config", lambda _data: (_ for _ in ()).throw(OSError("read-only"))
    )

    assert user_config.record_recent_capability("ldap-enum") == ["ldap-enum"]


def test_tui_compact_layout_and_visible_field_labels() -> None:
    app = ADAFAttackApp()
    app.on_resize(SimpleNamespace(size=SimpleNamespace(width=80)))
    assert app.has_class("compact")
    app.on_resize(SimpleNamespace(size=SimpleNamespace(width=160)))
    assert not app.has_class("compact")


def test_advanced_cli_surfaces_have_json_contracts(tmp_path: Path) -> None:
    session = tmp_path / "session"
    session.mkdir()
    (session / "session.json").write_text(json.dumps({"session_id": "s1"}), encoding="utf-8")
    (session / "findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {"id": "F-1", "title": "Review item", "severity": "high", "status": "open"}
                ]
            }
        ),
        encoding="utf-8",
    )
    (session / "graph.json").write_text(json.dumps({"nodes": [], "edges": []}), encoding="utf-8")
    (session / "events.jsonl").write_text(
        json.dumps({"type": "run.complete", "capability": "ldap-enum"}) + "\n",
        encoding="utf-8",
    )

    commands = [
        ["cockpit", "--session", str(session)],
        ["timeline", "--session", str(session)],
        ["copilot", "--session", str(session)],
        ["collaboration", "--session", str(session)],
        ["engagement", "package", "--session", str(session), "--preview"],
    ]
    for command in commands:
        result = runner.invoke(app, ["--format", "json", *command])
        assert result.exit_code == 0, f"{command}: {result.output}"
        assert json.loads(result.output)["ok"] is True
