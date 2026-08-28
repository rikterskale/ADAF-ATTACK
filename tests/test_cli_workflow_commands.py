"""Behavioral tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from adaf_attack.cli import app

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


def _run(ws: Path, *args: str) -> Any:
    return runner.invoke(app, ["--format", "json", "workflow", *args, "--workspace", str(ws)])


def _human(ws: Path, *args: str) -> Any:
    return runner.invoke(app, ["workflow", *args, "--workspace", str(ws)])


def _authorized_with_finding(ws: Path, finding_id: str = "F-1") -> None:
    _json(_run(ws, "authorize"))
    _json(_run(ws, "do", "run-discovery"))
    _json(_run(ws, "inject", "Issue", "--id", finding_id, "--severity", "high"))


def test_status_auto_starts_empty_workflow(tmp_path: Path) -> None:
    payload = _json(_run(tmp_path, "status"))
    assert payload["guidance"]["phase"] == "scoping"
    assert payload["guidance"]["next_action_id"] == "authorize-scope"
    # State is persisted so a second invocation resumes rather than restarts.
    assert (tmp_path / "workflow-state.json").is_file()
    again = _json(_run(tmp_path, "status"))
    assert again["workflow_id"] == payload["workflow_id"]


def test_full_lifecycle_start_to_closure(tmp_path: Path) -> None:
    _json(_run(tmp_path, "authorize"))
    _json(_run(tmp_path, "do", "run-discovery"))
    injected = _json(
        _run(
            tmp_path,
            "inject",
            "DCSync rights on service account",
            "--id",
            "ADAF-1",
            "--severity",
            "critical",
            "--confidence",
            "confirmed",
            "--asset",
            "dc-01",
        )
    )
    assert injected["guidance"]["risk_score"] == 100.0
    assert injected["guidance"]["next_action_id"] == "validate:ADAF-1"

    _json(_run(tmp_path, "do", "validate:ADAF-1"))
    decided = _json(_run(tmp_path, "decide", "decision:ADAF-1", "mitigate", "--rationale", "ok"))
    assert decided["guidance"]["next_action_id"] == "response:ADAF-1"

    _json(_run(tmp_path, "do", "response:ADAF-1"))
    _json(_run(tmp_path, "do", "verify:ADAF-1"))
    _json(_run(tmp_path, "transition", "ADAF-1", "closed", "--note", "retest clean"))

    nxt = _json(_run(tmp_path, "next"))
    assert nxt["recommendations"][0]["id"] == "generate-report"
    assert nxt["suggested_command"] == nxt["recommendations"][0]["suggested_command"]
    _json(_run(tmp_path, "do", "generate-report"))

    closed = _json(_run(tmp_path, "close"))
    assert closed["final_status"] == "complete"
    assert closed["guidance"]["phase"] == "closure"
    assert closed["guidance"]["progress"] == 100.0


def test_transition_accepts_explicit_artifact_evidence(tmp_path: Path) -> None:
    _authorized_with_finding(tmp_path, "F-NOTE")
    _json(_run(tmp_path, "transition", "F-NOTE", "validated", "--note", "observed"))
    _authorized_with_finding(tmp_path, "F-ARTIFACT")
    result = _run(
        tmp_path,
        "transition",
        "F-ARTIFACT",
        "validated",
        "--artifact",
        "evidence.json",
        "--pointer",
        "/status",
        "--sha256",
        "a" * 64,
        "--note",
        "observed",
    )
    assert _json(result)["guidance"]["phase"] == "validation"


def test_close_with_no_findings(tmp_path: Path) -> None:
    _json(_run(tmp_path, "authorize"))
    _json(_run(tmp_path, "do", "run-discovery"))
    closed = _json(_run(tmp_path, "close"))
    assert closed["final_status"] == "complete"
    # A definitive finish reads 100% even with no findings.
    assert closed["guidance"]["progress"] == 100.0


def test_unknown_action_returns_actionable_error(tmp_path: Path) -> None:
    result = _run(tmp_path, "do", "bogus-action")
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["error"]["code"] == "WORKFLOW_TRANSITION_INVALID"


def test_decision_action_rejected_by_do(tmp_path: Path) -> None:
    _json(_run(tmp_path, "authorize"))
    _json(_run(tmp_path, "do", "run-discovery"))
    _json(_run(tmp_path, "inject", "Finding", "--id", "ADAF-9", "--severity", "high"))
    _json(_run(tmp_path, "do", "validate:ADAF-9"))
    result = _run(tmp_path, "do", "decision:ADAF-9")
    assert result.exit_code == 1
    assert json.loads(result.output)["error"]["code"] == "WORKFLOW_TRANSITION_INVALID"


def test_query_and_correlate_findings(tmp_path: Path) -> None:
    _json(_run(tmp_path, "authorize"))
    _json(_run(tmp_path, "do", "run-discovery"))
    _json(_run(tmp_path, "inject", "A", "--id", "F-A", "--severity", "high", "--tag", "identity"))
    _json(_run(tmp_path, "inject", "B", "--id", "F-B", "--severity", "medium"))
    _json(_run(tmp_path, "correlate", "F-A", "F-B"))

    filtered = _json(_run(tmp_path, "findings", "--tag", "identity"))
    assert filtered["count"] == 1
    assert filtered["findings"][0]["id"] == "F-A"
    assert "F-B" in filtered["findings"][0]["related_findings"]


def test_import_session_adapts_canonical_findings(tmp_path: Path) -> None:
    session = tmp_path / "sess"
    session.mkdir()
    (session / "kerberoast.json").write_text('{"tickets": []}', encoding="utf-8")
    ws = tmp_path / "ws"
    _json(_run(ws, "authorize"))
    _json(_run(ws, "do", "run-discovery"))
    imported = _json(_run(ws, "import-session", "--session", str(session)))
    assert imported["imported_count"] == 1
    assert imported["imported"] == ["ADAF-KERB-001"]


def test_import_session_missing_directory(tmp_path: Path) -> None:
    result = _run(tmp_path, "import-session", "--session", str(tmp_path / "nope"))
    assert result.exit_code == 1
    assert json.loads(result.output)["error"]["code"] == "SESSION_NOT_FOUND"


def test_invalid_state_reported(tmp_path: Path) -> None:
    (tmp_path / "workflow-state.json").write_text("{ not json", encoding="utf-8")
    result = _run(tmp_path, "status")
    assert result.exit_code == 1
    assert json.loads(result.output)["error"]["code"] == "WORKFLOW_STATE_INVALID"


def test_snapshot_includes_guidance_and_recommendations(tmp_path: Path) -> None:
    payload = _json(_run(tmp_path, "snapshot"))
    assert payload["mode"] == "agent"
    assert "guidance" in payload
    assert "recommendations" in payload
    assert payload["phase"] == "scoping"


def test_human_output_renders_panel(tmp_path: Path) -> None:
    result = runner.invoke(app, ["workflow", "status", "--workspace", str(tmp_path)])
    assert result.exit_code == 0
    assert "Guided workflow status" in result.output
    assert "authorize-scope" in result.output


def test_actions_and_audit_queries(tmp_path: Path) -> None:
    _authorized_with_finding(tmp_path)
    actions = _json(_run(tmp_path, "actions", "--kind", "required"))
    assert any(a["id"] == "validate:F-1" for a in actions["actions"])
    all_actions = _json(_run(tmp_path, "actions", "--all"))
    assert all_actions["count"] >= actions["count"]

    audit = _json(_run(tmp_path, "audit"))
    assert audit["count"] > 0
    filtered = _json(_run(tmp_path, "audit", "--type", "finding.ingested"))
    assert filtered["count"] == 1


def test_enrich_updates_finding(tmp_path: Path) -> None:
    _authorized_with_finding(tmp_path)
    enriched = _json(
        _run(
            tmp_path,
            "enrich",
            "F-1",
            "--severity",
            "critical",
            "--confidence",
            "confirmed",
            "--impact",
            "Domain compromise",
            "--remediation",
            "Rotate keys",
            "--asset",
            "dc-01",
        )
    )
    assert enriched["guidance"]["risk_score"] > 0
    found = _json(_run(tmp_path, "findings", "--severity", "critical"))
    assert found["findings"][0]["id"] == "F-1"


def test_enrich_without_fields_is_rejected(tmp_path: Path) -> None:
    _authorized_with_finding(tmp_path)
    result = _run(tmp_path, "enrich", "F-1")
    assert result.exit_code == 1
    assert json.loads(result.output)["error"]["code"] == "REQUIRED_INPUT_MISSING"


def test_correlate_requires_two_ids(tmp_path: Path) -> None:
    _authorized_with_finding(tmp_path)
    result = _run(tmp_path, "correlate", "F-1")
    assert result.exit_code == 1
    assert json.loads(result.output)["error"]["code"] == "REQUIRED_INPUT_MISSING"


def test_transition_and_decide_error_paths(tmp_path: Path) -> None:
    _authorized_with_finding(tmp_path)
    # Illegal skip (open -> mitigated) is rejected by the engine.
    bad_transition = _run(tmp_path, "transition", "F-1", "mitigated")
    assert bad_transition.exit_code == 1
    assert json.loads(bad_transition.output)["error"]["code"] == "WORKFLOW_TRANSITION_INVALID"
    # decide() only accepts decision actions.
    bad_decision = _run(tmp_path, "decide", "validate:F-1", "mitigate")
    assert bad_decision.exit_code == 1
    assert json.loads(bad_decision.output)["error"]["code"] == "WORKFLOW_TRANSITION_INVALID"


def test_next_shows_no_recommendations_when_closed(tmp_path: Path) -> None:
    _json(_run(tmp_path, "authorize"))
    _json(_run(tmp_path, "do", "run-discovery"))
    _json(_run(tmp_path, "close"))
    nxt = _json(_run(tmp_path, "next"))
    # Closed workflows still expose the journey complete action as recommendations[0]
    # so next_step and the recommendation list never disagree.
    assert nxt["count"] >= 1
    assert nxt["journey_stage"] == "complete"
    assert nxt["suggested_command"].startswith("adaf-attack ")
    assert nxt["recommendations"][0]["suggested_command"] == nxt["suggested_command"]
    human = _human(tmp_path, "next")
    assert human.exit_code == 0
    assert "journey" in human.output.lower() or "sessions" in human.output.lower()


def test_import_into_closed_workflow_is_rejected(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    _json(_run(ws, "authorize"))
    _json(_run(ws, "do", "run-discovery"))
    _json(_run(ws, "close"))
    session = tmp_path / "sess"
    session.mkdir()
    (session / "kerberoast.json").write_text('{"tickets": []}', encoding="utf-8")
    result = _run(ws, "import-session", "--session", str(session))
    assert result.exit_code == 1
    assert json.loads(result.output)["error"]["code"] == "WORKFLOW_TRANSITION_INVALID"


def test_human_mode_read_commands(tmp_path: Path) -> None:
    _authorized_with_finding(tmp_path)
    for args in (["status"], ["next"], ["snapshot"], ["findings"], ["actions"], ["audit"]):
        result = _human(tmp_path, *args)
        assert result.exit_code == 0, result.output


def test_every_command_surfaces_invalid_state(tmp_path: Path) -> None:
    # A corrupt state file makes engine construction fail; every command must
    # surface it through the stable ActionableError contract rather than crash.
    session = tmp_path / "sess"
    session.mkdir()
    commands = [
        ["status"],
        ["next"],
        ["snapshot"],
        ["findings"],
        ["actions"],
        ["audit"],
        ["authorize"],
        ["inject", "Title"],
        ["enrich", "F-1", "--severity", "high"],
        ["correlate", "F-1", "F-2"],
        ["transition", "F-1", "validated"],
        ["decide", "decision:F-1", "mitigate"],
        ["do", "authorize-scope"],
        ["close"],
        ["import-session", "--session", str(session)],
    ]
    for args in commands:
        ws = tmp_path / ("_".join(a.replace(":", "-") for a in args if a.isalnum() or ":" in a))
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "workflow-state.json").write_text("{ not json", encoding="utf-8")
        result = _run(ws, *args)
        assert result.exit_code == 1, f"{args} did not fail: {result.output}"
        assert json.loads(result.output)["error"]["code"] == "WORKFLOW_STATE_INVALID", args
