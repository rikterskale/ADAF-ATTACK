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
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.outcomes import build_post_execution_outcome, record_detection_status
from adaf_attack.core.rollback import cleanup_dashboard
from adaf_attack.core.ux import (
    capability_prerequisites,
    diff_sessions,
    evaluate_prerequisites,
    export_plan_markdown,
    format_next_actions_block,
    format_stages_progress,
    unified_search,
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
    assert "beginner" in script
    assert "command" in script
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


def test_unified_search_includes_session_findings_graph_and_artifacts(tmp_path: Path) -> None:
    session = tmp_path / "session"
    session.mkdir()
    (session / "findings.json").write_text(
        json.dumps(
            {"findings": [{"id": "F-1", "title": "svc-backup exposure", "severity": "high"}]}
        ),
        encoding="utf-8",
    )
    (session / "graph.json").write_text(
        json.dumps(
            {
                "nodes": [{"id": "USER@SVC-BACKUP", "kind": "User", "properties": {}}],
                "edges": [],
            }
        ),
        encoding="utf-8",
    )
    (session / "svc-backup-evidence.json").write_text("{}", encoding="utf-8")

    result = unified_search("svc-backup", session=session)

    assert {item["type"] for item in result["results"]} >= {"finding", "identity", "evidence"}
    assert result["results"][0]["type"] == "finding"


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


def test_prerequisite_evaluation_distinguishes_unverified_and_missing(tmp_path: Path) -> None:
    assert evaluate_prerequisites("shadow-creds")["status"] == "unverified"
    session = tmp_path / "session"
    session.mkdir()
    (session / "events.jsonl").write_text(
        json.dumps({"capability": "acl-enum"}) + "\n", encoding="utf-8"
    )
    evaluated = evaluate_prerequisites("shadow-creds", session=session)
    assert evaluated["status"] == "satisfied"
    assert evaluated["satisfied"] == ["acl-enum"]


def test_post_execution_outcome_normalizes_evidence_and_rollback(tmp_path: Path) -> None:
    (tmp_path / "finding.json").write_text("{}", encoding="utf-8")
    (tmp_path / "cleanup.json").write_text(
        json.dumps([{"kind": "attribute", "status": "pending"}]), encoding="utf-8"
    )
    graph = AttackGraph()
    graph.add_node("USER@A", "User")
    graph.add_node("GROUP@DA", "Group")
    graph.add_edge("USER@A", "GROUP@DA", "GenericAll")

    outcome = build_post_execution_outcome(
        tmp_path,
        capability="acl-write",
        result={"ok": True},
        graph=graph,
        auth="username-only",
    )

    assert outcome["status"] == "success"
    assert outcome["rollback"]["status"] == "pending"
    assert outcome["graph_changes"]["edges_added"] == 1
    assert "finding.json" in outcome["evidence"]["artifacts"]


def test_cleanup_dashboard_reports_pending_and_restored_states(tmp_path: Path) -> None:
    assert cleanup_dashboard(tmp_path)["all_changes_restored"] is True
    (tmp_path / "cleanup.json").write_text(
        json.dumps(
            [
                {"kind": "acl", "status": "pending"},
                {"kind": "gpo", "status": "failed"},
            ]
        ),
        encoding="utf-8",
    )
    status = cleanup_dashboard(tmp_path)
    assert status["status"] == "blocked"
    assert status["rollback_readiness"] == "ready"
    assert status["all_changes_restored"] is False


def test_detection_status_updates_outcome_without_changing_offensive_result(
    tmp_path: Path,
) -> None:
    (tmp_path / "outcome.json").write_text(
        json.dumps({"status": "success", "offensive_success": True}), encoding="utf-8"
    )
    detection = record_detection_status(
        tmp_path,
        status="detected",
        notes="SIEM alert correlated",
        telemetry=["4769", "EDR alert"],
    )

    outcome = json.loads((tmp_path / "outcome.json").read_text(encoding="utf-8"))
    assert detection["status"] == "detected"
    assert outcome["offensive_success"] is True
    assert outcome["detection"]["observed_telemetry"] == ["4769", "EDR alert"]


def test_errors_command_shows_suggested() -> None:
    result = runner.invoke(app, ["--format", "json", "errors", "UNKNOWN_CAPABILITY"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["errors"][0].get("suggested_command")


def test_session_diff_reports_finding_identity_and_severity(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    for session in (first, second):
        session.mkdir()
        (session / "session.json").write_text(
            json.dumps({"session_id": session.name}), encoding="utf-8"
        )
        (session / "graph.json").write_text(
            json.dumps({"summary": {"nodes": 1, "edges": 0}}), encoding="utf-8"
        )
    (first / "findings.json").write_text(
        json.dumps({"findings": [{"id": "old", "severity": "low"}]}), encoding="utf-8"
    )
    (second / "findings.json").write_text(
        json.dumps({"findings": [{"id": "new", "severity": "high"}]}), encoding="utf-8"
    )

    result = diff_sessions(first, second)

    assert result["findings_added"] == ["new"]
    assert result["findings_removed"] == ["old"]
    assert result["severity_delta"] == {"high": 1, "low": -1}


def test_finding_triage_persists_status_tag_and_note(tmp_path: Path) -> None:
    session = tmp_path / "session"
    session.mkdir()
    (session / "findings.json").write_text(
        json.dumps({"findings": [{"id": "F-1", "title": "Open share", "severity": "medium"}]}),
        encoding="utf-8",
    )
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
            "F-1",
            "--status",
            "acknowledged",
            "--tag",
            "review",
            "--note",
            "Owner assigned",
        ],
    )
    assert result.exit_code == 0, result.output
    finding = json.loads((session / "findings.json").read_text(encoding="utf-8"))["findings"][0]
    assert finding["status"] == "acknowledged"
    assert finding["tags"] == ["review"]
    assert finding["triage_note"] == "Owner assigned"
