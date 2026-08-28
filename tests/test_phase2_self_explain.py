"""Behavioral coverage for Phase 2 self-explaining operator surfaces."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from textual.widgets import Input, Static
from typer.testing import CliRunner

import adaf_attack.capabilities  # noqa: F401  # register capabilities
from adaf_attack.cli import _doctor_payload, app
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import capability_registry
from adaf_attack.core.standout_ux import session_timeline
from adaf_attack.core.ux import destructive_confirmation_copy, operator_capability_contract
from adaf_attack.demo import materialize_demo_session
from adaf_attack.tui.app import ADAFAttackApp

runner = CliRunner()


def _json(result: Any) -> dict[str, Any]:
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def test_doctor_every_check_has_repair_text() -> None:
    for profile in ("offline", "user-readiness", "operator", "certipy"):
        payload = _doctor_payload(profile)
        assert payload["checks"]
        for check in payload["checks"]:
            assert isinstance(check.get("remediation"), str) and check["remediation"].strip(), check


def test_operator_capability_contract_covers_help_fields() -> None:
    cap = capability_registry.get("ldap-enum")
    assert cap is not None
    contract = operator_capability_contract(cap)
    assert contract["risk"]
    assert "approvals" in contract
    assert contract["rollback"]
    assert contract["rollback_implication"]
    assert contract["evidence_produced"]
    assert contract["stages"]
    assert "session.json" in contract["evidence_produced"]
    assert contract["rollback_command"].startswith("adaf-attack rollback")
    assert "--force" in contract["rollback_command"]
    assert "tickets" in contract["not_rolled_back"].lower()
    assert contract["after_run_command"] == "adaf-attack what-next ldap-enum"


def test_capability_help_and_explain_include_operator_contract() -> None:
    help_payload = _json(runner.invoke(app, ["--format", "json", "capability-help", "ldap-enum"]))
    capability = help_payload["capability"]
    assert capability["risk"]
    assert "approvals" in capability
    assert capability["rollback_implication"]
    assert capability["required_params"] is not None
    assert capability["evidence_produced"]
    assert capability["copy_ready_command"].startswith("adaf-attack run ldap-enum")

    explain = _json(runner.invoke(app, ["--format", "json", "explain", "ldap-enum"]))
    explained = explain["capability"]
    assert explained["risk"] == capability["risk"]
    assert explained["rollback_implication"]
    assert explained["evidence_produced"]


def test_plan_and_review_share_quoted_ready_command() -> None:
    plan = _json(
        runner.invoke(
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
            ],
        )
    )
    assert plan["suggested_command"] == plan["next_step"]
    assert "corp.example" in plan["next_step"]
    assert plan["approvals"] is not None
    assert plan["rollback_implication"]
    assert plan["evidence_produced"]
    assert plan["required_params"] is not None

    review = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "review",
                "ldap-enum",
                "-d",
                "corp.example",
                "--dc-ip",
                "10.0.0.10",
            ],
        )
    )
    assert review["suggested_command"] == plan["suggested_command"]


def test_timeline_summary_is_redacted_and_structured(tmp_path: Path) -> None:
    session = tmp_path / "demo-session"
    materialize_demo_session(session)
    events = session / "events.jsonl"
    events.write_text(
        json.dumps(
            {
                "ts": "2026-01-01T00:00:00Z",
                "type": "run.complete",
                "capability": "ldap-enum",
                "status": "ok",
                "duration_ms": 12,
                "correlation_id": "corr-1",
                "message": "password=SuperSecret123!",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    payload = session_timeline(session, limit=10)
    assert payload["ok"] is True
    assert payload["summary"]["secrets_redacted"] is True
    assert payload["summary"]["with_duration"] >= 1
    assert payload["summary"]["with_correlation"] >= 1
    assert payload["events"][0]["status"] == "ok"
    assert "SuperSecret123!" not in json.dumps(payload)


def test_tui_surfaces_expose_shared_operator_contract_before_run() -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            app.selected_cap = "ldap-enum"
            app.query_one("#domain", Input).value = "corp.example"
            app.query_one("#dc_ip", Input).value = "192.0.2.10"
            app.query_one("#username", Input).value = "operator"
            app._update_help()
            app._refresh_param_form()
            app._review_run()
            app._update_readiness()
            surfaces = (
                str(app.query_one("#help-panel", Static).render()),
                str(app.query_one("#param-title", Static).render()),
                str(app.query_one("#review-panel", Static).render()),
                str(app.query_one("#readiness", Static).render()),
            )
            for surface in surfaces:
                assert "Risk" in surface
                assert "Approvals" in surface
                assert "Rollback" in surface
                assert "Required -P" in surface
                assert "Evidence" in surface
                assert "Stages" in surface

    asyncio.run(exercise())


def test_destructive_confirmation_includes_rollback_and_exclusions() -> None:
    cap = capability_registry.get("dcsync")
    assert cap is not None
    copy = destructive_confirmation_copy(cap, domain="corp.example", dc_ip="10.0.0.10")
    assert "DESTRUCTIVE dcsync" in copy
    assert "corp.example" in copy
    assert "adaf-attack rollback" in copy
    assert "Not rolled back" in copy
    assert "tickets" in copy.lower()
    assert "cleanup.json" in copy


def test_plan_dcsync_includes_not_rolled_back() -> None:
    plan = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "plan",
                "dcsync",
                "-d",
                "corp.example",
                "--dc-ip",
                "10.0.0.10",
            ],
        )
    )
    assert plan["suggested_command"] == plan["next_step"]
    assert "adaf-attack run dcsync" in plan["next_step"]
    assert plan["rollback_command"].startswith("adaf-attack rollback")
    assert "tickets" in plan["not_rolled_back"].lower()
    assert plan["after_run_command"] == "adaf-attack what-next dcsync"
    assert plan["next_step"] != plan["after_run_command"]


def test_empty_sessions_names_guide_suggested_command(tmp_path: Path) -> None:
    guide = _json(runner.invoke(app, ["--format", "json", "guide", "--workspace", str(tmp_path)]))
    sessions = _json(
        runner.invoke(app, ["--format", "json", "sessions", "--workspace", str(tmp_path)])
    )
    assert sessions["ok"] is True
    assert sessions["sessions"] == []
    assert sessions["empty_state"]["next_command"] == guide["suggested_command"]
    assert sessions["suggested_command"] == guide["suggested_command"]


def test_empty_session_show_names_guide_next(tmp_path: Path) -> None:
    session = tmp_path / "empty-session"
    session.mkdir()
    (session / "session.json").write_text(
        json.dumps({"session_id": "empty-session"}),
        encoding="utf-8",
    )
    shown = _json(
        runner.invoke(
            app,
            ["--format", "json", "session", "show", "--session", str(session)],
        )
    )
    guide = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "guide",
                "--workspace",
                str(tmp_path),
                "--session",
                str(session),
            ],
        )
    )
    assert shown["finding_count"] == 0
    assert shown["empty_state"]["next_command"] == guide["suggested_command"]


def test_empty_rank_paths_names_guide_next(tmp_path: Path) -> None:
    graph = tmp_path / "graph.json"
    AttackGraph().save(graph)
    ranked = _json(runner.invoke(app, ["--format", "json", "rank-paths", "--graph", str(graph)]))
    guide = _json(runner.invoke(app, ["--format", "json", "guide"]))
    assert ranked["count"] == 0
    assert ranked["empty_state"]["next_command"] == guide["suggested_command"]


def test_tui_empty_sessions_names_guide_next(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = ADAFAttackApp(workspace=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app._show_sessions()
            surface = str(app.query_one("#session-panel", Static).render())
            assert "No sessions found." in surface
            assert "Next:" in surface
            journey = app._journey()
            assert str(journey.get("suggested_command")) in surface

    asyncio.run(exercise())
