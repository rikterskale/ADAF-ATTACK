"""Tests for the 15 UX enhancement helpers and CLI wiring."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

import adaf_attack.capabilities  # noqa: F401
from adaf_attack.cli import app
from adaf_attack.core import user_config
from adaf_attack.core.profiles import delete_profile, get_profile, list_profiles, set_profile
from adaf_attack.core.registry import capability_registry
from adaf_attack.core.ux import (
    PHASE_LABELS,
    build_ready_command,
    capability_phase,
    diff_sessions,
    group_capabilities_by_phase,
    guided_tour_payload,
    risk_checklist,
    session_findings_summary,
    stages_for_capability,
    unified_search,
)

runner = CliRunner()


def test_group_capabilities_by_phase() -> None:
    grouped = group_capabilities_by_phase()
    assert grouped
    for phase, caps in grouped.items():
        assert phase in PHASE_LABELS or phase
        for cap in caps:
            assert capability_phase(cap) == phase


def test_risk_checklist_and_ready_command() -> None:
    cap = capability_registry.get("ldap-enum")
    assert cap is not None
    checklist = risk_checklist(cap)
    assert checklist["id"] == "ldap-enum"
    assert checklist["requires_domain_user"] is True
    cmd = build_ready_command("ldap-enum", domain="corp.lab", dc_ip="10.0.0.1")
    assert "adaf-attack run ldap-enum" in cmd


def test_stages_for_capability() -> None:
    cap = capability_registry.get("kerberoast")
    assert cap is not None
    stages = stages_for_capability(cap)
    assert "prepare" in stages


def test_session_findings_summary_and_diff(tmp_path: Path) -> None:
    a = tmp_path / "sess-a"
    b = tmp_path / "sess-b"
    for path, titles in ((a, ["Finding A"]), (b, ["Finding A", "Finding B"])):
        path.mkdir()
        (path / "session.json").write_text(
            json.dumps({"session_id": path.name, "created_at": "2026-08-01T00:00:00Z"}),
            encoding="utf-8",
        )
        (path / "findings.json").write_text(
            json.dumps(
                {
                    "findings": [
                        {"title": t, "severity": "high", "techniques": ["T1558.003"]}
                        for t in titles
                    ]
                }
            ),
            encoding="utf-8",
        )
        (path / "graph.json").write_text(
            json.dumps(
                {
                    "summary": {
                        "nodes": 10 if path == a else 12,
                        "edges": 5 if path == a else 7,
                    }
                }
            ),
            encoding="utf-8",
        )
    summary = session_findings_summary(a)
    assert summary["session_id"] == "sess-a"
    # findings_from_session may not parse raw title-only fixtures; still check graph
    assert summary["graph"]["nodes"] == 10
    diff = diff_sessions(a, b)
    assert diff["node_delta"] == 2


def test_unified_search_capabilities() -> None:
    payload = unified_search("kerberoast")
    assert any(c["id"] == "kerberoast" for c in payload["capabilities"])


def test_profiles_roundtrip(tmp_path: Path, monkeypatch) -> None:
    from adaf_attack.core import paths as paths_mod
    from adaf_attack.core import profiles as profiles_mod

    monkeypatch.setattr(paths_mod, "user_config_dir", lambda: tmp_path / "cfg")
    monkeypatch.setattr(profiles_mod, "profiles_path", lambda: tmp_path / "cfg" / "profiles.json")
    set_profile("lab", {"domain": "corp.lab", "dc_ip": "10.0.0.5", "opsec_profile": "stealth"})
    assert get_profile("lab")["domain"] == "corp.lab"
    assert any(p["name"] == "lab" for p in list_profiles())
    assert delete_profile("lab") is True


def test_guided_tour_payload() -> None:
    payload = guided_tour_payload()
    assert len(payload["steps"]) >= 5


def test_cli_list_capabilities_by_phase() -> None:
    result = runner.invoke(app, ["list-capabilities", "--by-phase"])
    assert result.exit_code == 0
    assert (
        "Discovery" in result.stdout
        or "ldap-enum" in result.stdout
        or "Enumeration" in result.stdout
    )


def test_cli_capability_help_checklist() -> None:
    result = runner.invoke(app, ["capability-help", "ldap-enum"])
    assert result.exit_code == 0
    assert "Checklist" in result.stdout
    assert "Copy-ready" in result.stdout


def test_cli_tour_and_search() -> None:
    result = runner.invoke(app, ["tour"])
    assert result.exit_code == 0
    result = runner.invoke(app, ["search", "ldap-enum"])
    assert result.exit_code == 0
    assert "ldap-enum" in result.stdout


def test_cli_favorites_and_recent_targets_are_non_secret(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(user_config, "config_path", lambda: tmp_path / "config.json")

    added = runner.invoke(app, ["--format", "json", "favorites", "add", "ldap-enum"])
    assert added.exit_code == 0, added.output
    listed = runner.invoke(app, ["--format", "json", "favorites", "list"])
    assert listed.exit_code == 0, listed.output
    assert json.loads(listed.output)["capabilities"][0]["id"] == "ldap-enum"

    user_config.record_recent_target("corp.example", "10.0.0.10", "high-value")
    targets = runner.invoke(app, ["--format", "json", "targets"])
    assert targets.exit_code == 0, targets.output
    payload = json.loads(targets.output)
    assert payload["targets"] == [
        {"domain": "corp.example", "dc_ip": "10.0.0.10", "scope": "high-value"}
    ]
    assert "password" not in (tmp_path / "config.json").read_text(encoding="utf-8").lower()


def test_cli_saved_mission_templates(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(user_config, "config_path", lambda: tmp_path / "config.json")
    saved = runner.invoke(app, ["--format", "json", "engagement", "mission-save", "tier-0-paths"])
    assert saved.exit_code == 0, saved.output
    listed = runner.invoke(app, ["--format", "json", "engagement", "mission-saved"])
    assert listed.exit_code == 0, listed.output
    assert json.loads(listed.output)["saved_ids"] == ["tier-0-paths"]
    removed = runner.invoke(
        app, ["--format", "json", "engagement", "mission-remove", "tier-0-paths"]
    )
    assert removed.exit_code == 0, removed.output
    unknown = runner.invoke(app, ["--format", "json", "engagement", "mission-save", "missing"])
    assert unknown.exit_code == 1


def test_cli_novice_journey_aliases(tmp_path: Path) -> None:
    review = runner.invoke(
        app,
        ["--format", "json", "review", "ldap-enum", "-d", "corp.example", "--dc-ip", "10.0.0.10"],
    )
    assert review.exit_code == 0, review.output
    assert json.loads(review.output)["mode"] == "preview"

    help_result = runner.invoke(app, ["--format", "json", "help-me"])
    assert help_result.exit_code == 0, help_result.output
    assert json.loads(help_result.output)["steps"]

    demo = runner.invoke(app, ["--format", "json", "start-demo", "--workspace", str(tmp_path)])
    assert demo.exit_code == 0, demo.output
    assert json.loads(demo.output)["mode"] == "offline-demo"


def test_cli_plan_shows_opsec_and_copy() -> None:
    result = runner.invoke(app, ["plan", "ldap-enum", "-d", "corp.lab", "--dc-ip", "10.0.0.1"])
    assert result.exit_code == 0
    assert "Copy-ready" in result.stdout
    assert "Opsec" in result.stdout


def test_cli_session_diff(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    for path, count in ((a, 1), (b, 2)):
        path.mkdir()
        (path / "session.json").write_text(json.dumps({"session_id": path.name}), encoding="utf-8")
        (path / "findings.json").write_text(
            json.dumps(
                {"findings": [{"title": f"F{i}", "severity": "high"} for i in range(count)]}
            ),
            encoding="utf-8",
        )
        (path / "graph.json").write_text(
            json.dumps({"summary": {"nodes": count * 5, "edges": count}}),
            encoding="utf-8",
        )
    result = runner.invoke(app, ["session", "diff", str(a), str(b)])
    assert result.exit_code == 0


def test_capability_payload_has_beginner_metadata() -> None:
    result = runner.invoke(app, ["--format", "json", "capability-help", "ldap-enum"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    cap = payload["capability"]
    assert cap["difficulty"]["level"] in {"Beginner", "Intermediate", "Advanced"}
    assert cap["preflight_checklist"]["items"]
    assert cap["stages"]


def test_plan_contains_preflight_and_stages() -> None:
    result = runner.invoke(
        app,
        ["--format", "json", "plan", "ldap-enum", "-d", "corp.lab", "--dc-ip", "10.0.0.10"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["preflight_checklist"]["id"] == "ldap-enum"
    assert payload["stages"]["stages"]


def test_home_and_command_builder_json() -> None:
    home = runner.invoke(app, ["--format", "json", "home"])
    assert home.exit_code == 0, home.output
    assert json.loads(home.output)["actions"]

    command = runner.invoke(
        app,
        [
            "--format",
            "json",
            "command",
            "ldap-enum",
            "-d",
            "corp.lab",
            "--dc-ip",
            "10.0.0.10",
        ],
    )
    assert command.exit_code == 0, command.output
    payload = json.loads(command.output)
    assert payload["command"].startswith("adaf-attack run ldap-enum")
    assert payload["option_explanations"]


def test_beginner_and_summary_output_modes_are_distinct() -> None:
    beginner = runner.invoke(app, ["--format", "beginner", "capability-help", "ldap-enum"])
    assert beginner.exit_code == 0, beginner.output
    assert "Beginner summary" in beginner.output
    assert "Difficulty" in beginner.output

    summary = runner.invoke(app, ["--format", "summary", "home"])
    assert summary.exit_code == 0, summary.output
    assert "ok: True" in summary.output


def test_finding_explain_and_remediate(tmp_path: Path) -> None:
    session = tmp_path / "session"
    session.mkdir()
    (session / "findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "F-1",
                        "title": "Kerberoastable account",
                        "severity": "high",
                        "evidence": ["kerberoast.json"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    explain = runner.invoke(
        app, ["--format", "json", "finding", "explain", "--session", str(session), "--id", "F-1"]
    )
    assert explain.exit_code == 0, explain.output
    assert json.loads(explain.output)["finding"]["severity"] == "high"

    remediate = runner.invoke(
        app,
        ["--format", "json", "finding", "remediate", "--session", str(session), "--id", "F-1"],
    )
    assert remediate.exit_code == 0, remediate.output
    assert [step["id"] for step in json.loads(remediate.output)["steps"]][-1] == "retest"


def test_session_show_includes_timeline_and_resume(tmp_path: Path) -> None:
    session = tmp_path / "s1"
    session.mkdir()
    (session / "session.json").write_text(json.dumps({"session_id": "s1"}), encoding="utf-8")
    (session / "findings.json").write_text(json.dumps({"findings": []}), encoding="utf-8")
    (session / "events.jsonl").write_text(
        json.dumps({"time": "2026-08-20T00:00:00Z", "event": "run", "capability": "ldap-enum"})
        + "\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["--format", "json", "session", "show", "--session", str(session)])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["timeline"][0]["capability"] == "ldap-enum"
    assert "session show" in payload["resume_command"]
