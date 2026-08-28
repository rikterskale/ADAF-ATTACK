"""Behavioral tests for the unified operator journey."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from adaf_attack.cli import app
from adaf_attack.core import journey
from adaf_attack.core.workflow_engine import WorkflowAction, WorkflowEngine, WorkflowError
from adaf_attack.demo import materialize_demo_session

runner = CliRunner()


@pytest.fixture(autouse=True)
def _consistent_test_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    import adaf_attack.cli as cli

    monkeypatch.setattr(
        cli, "_pip_consistency_check", lambda: (True, "No broken requirements found.")
    )


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
    assert "quickstart" in payload["primary_action"]["suggested_command"]
    assert "--workspace" in payload["primary_action"]["suggested_command"]
    assert payload["primary_action"]["risk"] == "OBSERVE"
    assert payload["primary_action"]["recovery_command"].startswith("adaf-attack guide")
    assert payload["entry_criteria"]
    assert payload["exit_criteria"]
    assert payload["ok"] is True


def test_journey_quotes_workspace_paths_with_spaces(tmp_path: Path) -> None:
    spaced = tmp_path / "my workspace"
    spaced.mkdir()
    command = journey.suggested_command_for_action(
        WorkflowAction(
            "authorize-scope", "Confirm scope", "Record approval", "scoping", "required"
        ),
        workspace=spaced,
    )
    assert "authorize" in command
    assert "my workspace" in command or "my\\ workspace" in command or "'my workspace'" in command
    # Raw unquoted space between flag and path tokens must not appear.
    assert "--workspace my workspace" not in command


def test_quote_path_uses_forward_slashes_on_windows(monkeypatch) -> None:
    import os as os_mod

    monkeypatch.setattr(os_mod, "name", "nt")
    quoted = journey.quote_path(r"C:\Users\op\quickstart\demo-session")
    assert "\\" not in quoted
    assert "C:/Users/op/quickstart/demo-session" in quoted


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


def test_journey_follows_authorized_workflow_without_demo(tmp_path: Path) -> None:
    """Authorized workflows must not be forced back to quickstart without a demo."""
    engine = WorkflowEngine(tmp_path)
    engine.start(actor="test")
    engine.complete_action("authorize-scope", actor="test")
    payload = journey.snapshot(workspace=tmp_path, doctor={"ok": True, "checks": []})
    assert payload["stage"] != "first-success"
    assert payload["primary_action"]["id"] != "quickstart"


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
    what_next = _json(
        runner.invoke(app, ["--format", "json", "what-next", "--workspace", str(tmp_path)])
    )
    assert what_next["context"] == "journey"
    assert what_next["next_step"] == guide["primary_action"]["suggested_command"]
    assert what_next["suggested_command"] == guide["suggested_command"]


def test_capability_what_next_keeps_journey_primary(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    guide = _json(runner.invoke(app, ["--format", "json", "guide", "--workspace", str(tmp_path)]))
    what_next = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "what-next",
                "ldap-enum",
                "--workspace",
                str(tmp_path),
            ],
        )
    )
    assert what_next["context"] == "journey"
    assert what_next["completed_capability"] == "ldap-enum"
    assert what_next["stage"] == guide["stage"]
    assert what_next["suggested_command"] == guide["suggested_command"]
    assert what_next["recovery_command"] == guide["recovery_command"]


def test_guide_what_next_workflow_next_agree_with_session(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    session = tmp_path / "demo-session"
    materialize_demo_session(session)
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
    what_next = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "what-next",
                "--workspace",
                str(tmp_path),
                "--session",
                str(session),
            ],
        )
    )
    workflow_next = _json(
        runner.invoke(
            app,
            ["--format", "json", "workflow", "next", "--workspace", str(tmp_path)],
        )
    )
    assert what_next["context"] == "journey"
    assert what_next["next_step"] == guide["next_step"]
    assert workflow_next["next_step"] == guide["next_step"]
    assert guide["primary_action"]["rollback_implication"]
    assert guide["recovery_command"].startswith("adaf-attack guide")


def test_evidence_basis_matches_across_all_next_action_surfaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    session = tmp_path / "demo-session"
    materialize_demo_session(session)
    engine = WorkflowEngine(tmp_path)
    engine.start(actor="test")
    engine.complete_action("authorize-scope", actor="test")
    journey.import_session_findings(tmp_path, session, actor="test")

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
    what_next = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "what-next",
                "--workspace",
                str(tmp_path),
                "--session",
                str(session),
            ],
        )
    )
    workflow_next = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "workflow",
                "next",
                "--workspace",
                str(tmp_path),
                "--session",
                str(session),
            ],
        )
    )

    evidence = guide["primary_action"]["evidence_basis"]
    assert {item["kind"] for item in evidence} >= {"finding", "artifact"}
    artifact = next(item for item in evidence if item["kind"] == "artifact")
    assert artifact["ref"].endswith((".json#/dcsync_principals", ".json#/esc1_candidates"))
    assert len(artifact["sha256"]) == 64
    assert what_next["primary_action"]["evidence_basis"] == evidence
    assert workflow_next["primary_action"]["evidence_basis"] == evidence
    assert workflow_next["recommendations"][0]["evidence_basis"] == evidence


def test_invalid_session_failure_matches_across_guided_surfaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    missing = tmp_path / "missing-session"
    invocations = (
        ["guide", "--workspace", str(tmp_path), "--session", str(missing)],
        ["what-next", "--workspace", str(tmp_path), "--session", str(missing)],
        [
            "workflow",
            "next",
            "--workspace",
            str(tmp_path),
            "--session",
            str(missing),
        ],
    )
    payloads: list[dict[str, Any]] = []
    for args in invocations:
        result = runner.invoke(app, ["--format", "json", *args])
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["ok"] is False
        assert payload["error"]["code"] == "SESSION_NOT_FOUND"
        assert payload["stage" if args[0] != "workflow" else "journey_stage"] == ("session-blocked")
        payloads.append(payload)
    commands = {payload["suggested_command"] for payload in payloads}
    recoveries = {payload["recovery_command"] for payload in payloads}
    assert commands == {"adaf-attack sessions --limit 10"}
    assert len(recoveries) == 1
    assert "--session" not in recoveries.pop()


def test_invalid_session_json_is_rejected(tmp_path: Path) -> None:
    session = tmp_path / "bad-session"
    session.mkdir()
    (session / "session.json").write_text("not-json", encoding="utf-8")
    payload = journey.snapshot(
        workspace=tmp_path,
        session=session,
        doctor={"ok": True, "checks": []},
    )
    assert payload["ok"] is False
    assert payload["stage"] == "session-blocked"
    assert payload["error"]["code"] == "SESSION_NOT_FOUND"


def test_every_next_action_suggestion_has_evidence_basis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    what_next = _json(
        runner.invoke(
            app,
            ["--format", "json", "what-next", "--workspace", str(tmp_path)],
        )
    )
    assert all(item["evidence_basis"] for item in what_next["suggestions"])
    after_capability = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "what-next",
                "ldap-enum",
                "--workspace",
                str(tmp_path),
            ],
        )
    )
    assert all(item["evidence_basis"] for item in after_capability["suggestions"])
    workflow_next = _json(
        runner.invoke(
            app,
            ["--format", "json", "workflow", "next", "--workspace", str(tmp_path)],
        )
    )
    assert all(item["evidence_basis"] for item in workflow_next["recommendations"])


def test_tour_marks_progress(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    materialize_demo_session(tmp_path / "demo-session")
    payload = _json(runner.invoke(app, ["--format", "json", "tour"]))
    assert payload["ok"] is True
    guide_step = next(step for step in payload["steps"] if step["id"] == "guide")
    assert guide_step["done"] is True
    demo_step = next(step for step in payload["steps"] if step["id"] == "demo")
    assert demo_step["done"] is True
    assert payload["next_step"]
    assert "guide" in payload["next_step"] or "workflow" in payload["next_step"]


def test_tour_and_home_match_guide_with_workspace_session(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    session = tmp_path / "demo-session"
    materialize_demo_session(session)
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
    tour = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "tour",
                "--workspace",
                str(tmp_path),
                "--session",
                str(session),
            ],
        )
    )
    home = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "home",
                "--workspace",
                str(tmp_path),
                "--session",
                str(session),
            ],
        )
    )
    help_me = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "help-me",
                "--workspace",
                str(tmp_path),
                "--session",
                str(session),
            ],
        )
    )
    assert tour["suggested_command"] == guide["suggested_command"]
    assert home["suggested_command"] == guide["suggested_command"]
    assert help_me["suggested_command"] == guide["suggested_command"]
    assert tour["recovery_command"] == guide["recovery_command"]
    assert home["recovery_command"] == guide["recovery_command"]
    assert help_me["recovery_command"] == guide["recovery_command"]
    assert tour["stage"] == guide["stage"]
    assert home["stage"] == guide["stage"]


@pytest.mark.parametrize("command", ("tour", "home", "help-me"))
def test_tour_home_and_help_me_fail_like_guide_for_invalid_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    missing = tmp_path / "missing-session"
    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            command,
            "--workspace",
            str(tmp_path),
            "--session",
            str(missing),
        ],
    )
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "SESSION_NOT_FOUND"
    assert payload["stage"] == "session-blocked"
    assert payload["suggested_command"] == "adaf-attack sessions --limit 10"
    assert payload["recovery_command"].startswith("adaf-attack guide")
    assert "--session" not in payload["recovery_command"]


def test_workflow_next_includes_suggested_command(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["--format", "json", "workflow", "next", "--workspace", str(tmp_path)]
    )
    payload = _json(result)
    assert payload["count"] >= 1
    assert "suggested_command" in payload["recommendations"][0]
    assert payload["recommendations"][0]["suggested_command"].startswith("adaf-attack ")
    # Journey primary wins even when the engine still wants authorize-scope.
    assert payload["next_step"] == payload["recommendations"][0]["suggested_command"]
    assert payload["suggested_command"] == payload["recommendations"][0]["suggested_command"]
    assert "quickstart" in payload["suggested_command"]


def test_workflow_next_recommendations_match_guide_with_session(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    session = tmp_path / "demo-session"
    materialize_demo_session(session)
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
    workflow_next = _json(
        runner.invoke(
            app,
            [
                "--format",
                "json",
                "workflow",
                "next",
                "--workspace",
                str(tmp_path),
                "--session",
                str(session),
            ],
        )
    )
    assert workflow_next["suggested_command"] == guide["suggested_command"]
    assert workflow_next["recommendations"][0]["suggested_command"] == guide["suggested_command"]


def test_import_session_findings_unlocks_validation(tmp_path: Path) -> None:
    session = tmp_path / "demo-session"
    materialize_demo_session(session)
    engine = WorkflowEngine(tmp_path)
    engine.start(actor="test")
    engine.complete_action("authorize-scope", actor="test")
    result = journey.import_session_findings(tmp_path, session, actor="test")
    assert result["ok"] is True
    assert result["count"] >= 1
    engine = WorkflowEngine(tmp_path)
    assert "scope-authorized" in engine.state.completed_steps
    assert engine.state.findings
    recs = engine.recommendations(limit=5)
    assert any(item.id.startswith("validate:") for item in recs)


def test_import_session_findings_requires_authorized_scope(tmp_path: Path) -> None:
    session = tmp_path / "demo-session"
    materialize_demo_session(session)
    with pytest.raises(WorkflowError, match="Authorize scope"):
        journey.import_session_findings(tmp_path, session, actor="test")


def test_guide_advance_requires_human_output_mode(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    blocked = runner.invoke(
        app, ["--format", "json", "guide", "--workspace", str(tmp_path), "--advance"]
    )
    assert blocked.exit_code != 0


def test_guide_advance_quickstart_uses_suggested_workspace(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    result = runner.invoke(app, ["guide", "--workspace", str(tmp_path), "--advance"])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "demo-session" / "session.json").is_file()
    assert not (tmp_path / "quickstart" / "demo-session").exists()


def test_guide_advance_does_not_record_authorization(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    session = tmp_path / "demo-session"
    materialize_demo_session(session)
    result = runner.invoke(
        app,
        [
            "guide",
            "--workspace",
            str(tmp_path),
            "--session",
            str(session),
            "--advance",
        ],
    )
    assert result.exit_code != 0
    assert "GUIDE_ADVANCE_UNSAFE" in result.output
    engine = WorkflowEngine(tmp_path)
    assert "scope-authorized" not in engine.state.completed_steps


@pytest.mark.parametrize(
    "action_id",
    (
        "authorize-scope",
        "run-discovery",
        "validate:F-1",
        "response:F-1",
        "verify:F-1",
        "generate-report",
    ),
)
def test_workflow_actions_cannot_be_auto_advanced(action_id: str) -> None:
    action = WorkflowAction(action_id, "Action", "Operator work", "validation", "required")
    assert journey.action_is_advance_safe(action) is False


def test_corrupt_workflow_state_blocks_guide(tmp_path: Path) -> None:
    (tmp_path / "workflow-state.json").write_text("not-json", encoding="utf-8")
    payload = journey.snapshot(workspace=tmp_path, doctor={"ok": True, "checks": []})
    assert payload["ok"] is False
    assert payload["error"]["code"] == "WORKFLOW_STATE_INVALID"
    assert payload["primary_action"]["id"] == "repair-workflow-state"
    assert payload["suggested_command"].startswith("adaf-attack support-bundle")


@pytest.mark.parametrize("capability", (None, "ldap-enum"))
def test_corrupt_workflow_state_blocks_what_next(
    tmp_path: Path,
    monkeypatch,
    capability: str | None,
) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    (tmp_path / "workflow-state.json").write_text("not-json", encoding="utf-8")
    args = ["--format", "json", "what-next"]
    if capability is not None:
        args.append(capability)
    args.extend(["--workspace", str(tmp_path)])
    payload = json.loads(runner.invoke(app, args).output)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "WORKFLOW_STATE_INVALID"
    assert payload["journey"]["ok"] is False


def test_corrupt_workflow_state_precedes_advance_guard(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_ATTACK_WORKSPACE", str(tmp_path))
    (tmp_path / "workflow-state.json").write_text("not-json", encoding="utf-8")
    result = runner.invoke(app, ["guide", "--workspace", str(tmp_path), "--advance"])
    assert result.exit_code != 0
    assert "WORKFLOW_STATE_INVALID" in result.output
    assert "GUIDE_ADVANCE_UNSAFE" not in result.output
