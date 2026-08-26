"""Behavioral tests for the unified operator journey."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from adaf_attack.cli import app
from adaf_attack.core import journey
from adaf_attack.core.workflow_engine import WorkflowAction, WorkflowEngine
from adaf_attack.demo import materialize_demo_session

runner = CliRunner()


def _json(result: Any) -> dict[str, Any]:
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def test_suggested_command_for_authorize() -> None:
    action = WorkflowAction(
        "authorize-scope",
        "Confirm scope",
        "Record approval",
        "scoping",
        "required",
    )
    command = journey.suggested_command_for_action(action, workspace=Path("/tmp/ws"))
    assert "workflow authorize" in command
    assert "--workspace" in command


def test_suggested_command_for_validate_and_decision() -> None:
    validate = WorkflowAction(
        "validate:F-1",
        "Validate",
        "Confirm",
        "validation",
        "required",
        finding_ids=["F-1"],
    )
    decide = WorkflowAction(
        "decision:F-1",
        "Decide",
        "Choose",
        "prioritization",
        "decision",
        finding_ids=["F-1"],
    )
    assert journey.suggested_command_for_action(validate).endswith("workflow do validate:F-1")
    assert "workflow decide decision:F-1" in journey.suggested_command_for_action(decide)


def test_journey_first_success_without_demo(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    payload = journey.snapshot(workspace=tmp_path, doctor={"ok": True, "checks": []})
    assert payload["stage"] == "first-success"
    assert payload["primary_action"]["id"] == "quickstart"
    assert payload["primary_action"]["suggested_command"] == "adaf-attack quickstart"
    assert payload["ok"] is True


def test_journey_install_blocked(tmp_path: Path) -> None:
    doctor = {
        "ok": False,
        "checks": [
            {
                "id": "packaged-demo",
                "status": "error",
                "detail": "missing",
                "remediation": "Reinstall the release artifact.",
            }
        ],
    }
    payload = journey.snapshot(workspace=tmp_path, doctor=doctor)
    assert payload["stage"] == "install-blocked"
    assert payload["ok"] is False
    assert payload["primary_action"]["id"] == "repair-install"
    assert "doctor" in payload["primary_action"]["suggested_command"]


def test_journey_operates_from_workflow(tmp_path: Path) -> None:
    materialize_demo_session(tmp_path / "demo-session")
    engine = WorkflowEngine(tmp_path)
    engine.start(actor="test")
    engine.complete_action("authorize-scope", actor="test")
    payload = journey.snapshot(workspace=tmp_path, doctor={"ok": True, "checks": []})
    assert payload["stage"] in {"discover", "operate"}
    assert "suggested_command" in payload["primary_action"]
    assert payload["primary_action"]["suggested_command"]
    assert payload["workflow"]["phase"] in {
        "discovery",
        "validation",
        "scoping",
        "prioritization",
        "response",
        "verification",
        "reporting",
        "closure",
    }


def test_guide_json_contract(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    result = runner.invoke(app, ["--format", "json", "guide", "--workspace", str(tmp_path)])
    payload = _json(result)
    assert payload["ok"] is True
    assert payload["stage"] == "first-success"
    assert payload["primary_action"]["suggested_command"]
    assert payload["next_step"] == payload["primary_action"]["suggested_command"]
    assert isinstance(payload["breadcrumb"], list)
    assert "blockers" in payload


def test_what_next_delegates_to_journey(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    guide = _json(runner.invoke(app, ["--format", "json", "guide", "--workspace", str(tmp_path)]))
    what_next = _json(runner.invoke(app, ["--format", "json", "what-next"]))
    assert what_next["context"] == "journey"
    assert what_next["next_step"] == guide["primary_action"]["suggested_command"]


def test_tour_marks_progress(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    materialize_demo_session(tmp_path / "demo-session")
    payload = _json(runner.invoke(app, ["--format", "json", "tour"]))
    assert payload["ok"] is True
    demo_step = next(step for step in payload["steps"] if step["id"] == "demo")
    assert demo_step["done"] is True
    assert payload["next_step"]
    assert "guide" in payload["next_step"] or "workflow" in payload["next_step"]


def test_workflow_next_includes_suggested_command(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["--format", "json", "workflow", "next", "--workspace", str(tmp_path)]
    )
    payload = _json(result)
    assert payload["count"] >= 1
    assert "suggested_command" in payload["recommendations"][0]
    assert payload["recommendations"][0]["suggested_command"].startswith("adaf-attack ")
    assert payload["next_step"] == payload["recommendations"][0]["suggested_command"]


def test_import_session_findings_unlocks_validation(tmp_path: Path) -> None:
    session = tmp_path / "demo-session"
    materialize_demo_session(session)
    result = journey.import_session_findings(tmp_path, session, actor="test")
    assert result["ok"] is True
    assert result["count"] >= 1
    engine = WorkflowEngine(tmp_path)
    assert "scope-authorized" in engine.state.completed_steps
    assert engine.state.findings
    recs = engine.recommendations(limit=5)
    assert any(item.id.startswith("validate:") for item in recs)


def test_guide_advance_quickstart(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    # Non-interactive / JSON mode must refuse --advance.
    blocked = runner.invoke(
        app, ["--format", "json", "guide", "--workspace", str(tmp_path), "--advance"]
    )
    assert blocked.exit_code != 0
