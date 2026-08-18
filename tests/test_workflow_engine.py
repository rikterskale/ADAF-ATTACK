"""Finding-driven workflow engine coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adaf_attack.core.workflow_engine import (
    FindingRecord,
    WorkflowAction,
    WorkflowEngine,
    WorkflowError,
    WorkflowGuidance,
    finding_from_document,
)


def test_custom_rules_and_retry_safe_actions(tmp_path: Path) -> None:
    def rule(state):
        if any(item.severity == "critical" for item in state.open_findings):
            return [
                WorkflowAction(
                    "custom:escalate",
                    "Escalate critical exposure",
                    "Notify the incident owner and preserve the evidence bundle.",
                    "prioritization",
                    "required",
                )
            ]
        return []

    engine = WorkflowEngine(tmp_path, rules=[rule])
    engine.start()
    engine.complete_action("authorize-scope")
    engine.complete_action("run-discovery")
    engine.ingest_finding({"id": "F-CRIT", "title": "Critical exposure", "severity": "critical"})
    assert any(item.id == "custom:escalate" for item in engine.query_actions(kind="required"))
    engine.complete_action("custom:escalate")
    revision = engine.state.revision
    engine.complete_action("custom:escalate")
    assert engine.state.revision == revision


def test_query_findings_supports_operational_filters(tmp_path: Path) -> None:
    engine = WorkflowEngine(tmp_path)
    engine.ingest_finding(
        {
            "id": "F-FILTER",
            "title": "Asset issue",
            "source": "scanner",
            "tags": ["identity"],
            "affected_assets": ["dc-01"],
        }
    )
    assert (
        engine.query_findings(source="scanner", tag="identity", asset="dc-01")[0].id == "F-FILTER"
    )


def test_engine_drives_finding_lifecycle_and_persists(tmp_path: Path) -> None:
    engine = WorkflowEngine(tmp_path, title="Lab assessment")
    engine.start()
    assert engine.state.pending_actions["authorize-scope"].kind == "required"

    engine.complete_action("authorize-scope")
    engine.complete_action("run-discovery")
    finding = engine.ingest_finding(
        FindingRecord(
            "F-1",
            "Dangerous delegation",
            severity="critical",
            confidence="observed",
            affected_assets=["COMPUTER01", "DC01"],
        )
    )
    assert finding.priority > 80
    assert engine.recommendations()[0].id == "validate:F-1"

    engine.transition_finding("F-1", "validated")
    assert engine.recommendations()[0].id == "decision:F-1"
    with pytest.raises(WorkflowError, match="Decision cannot be empty"):
        engine.decide("decision:F-1", "")
    engine.decide("decision:F-1", "confirm-impact", rationale="Approved validation plan")
    engine.transition_finding("F-1", "exploited", actor="operator")
    engine.transition_finding("F-1", "mitigated", actor="operator")
    assert engine.recommendations()[0].id == "verify:F-1"
    engine.complete_action("verify:F-1")
    engine.transition_finding("F-1", "closed", evidence={"artifact": "mitigation-validation.json"})
    assert engine.query_findings(status="closed")[0].id == "F-1"
    assert engine.state.risk_score == 0
    assert engine.recommendations()[0].id == "generate-report"
    engine.complete_action("generate-report")
    engine.close()
    assert engine.state.status == "complete"

    reloaded = WorkflowEngine(tmp_path)
    assert reloaded.state.workflow_id == engine.state.workflow_id
    assert reloaded.state.findings["F-1"].status == "closed"
    assert reloaded.state.audit_log
    assert (
        json.loads((tmp_path / "workflow-state.json").read_text(encoding="utf-8"))["revision"] > 0
    )


def test_engine_supports_injection_enrichment_correlation_and_overrides(tmp_path: Path) -> None:
    engine = WorkflowEngine(tmp_path)
    one = engine.inject_finding("Operator observation", id="F-1", severity="medium")
    two = engine.ingest_finding({"id": "F-2", "title": "Observed path", "severity": "high"})
    engine.correlate([one.id, two.id], relation="same-control")
    assert engine.state.findings["F-1"].related_findings == ["F-2"]
    assert "same-control" in engine.state.findings["F-2"].tags
    engine.enrich_finding("F-1", confidence="confirmed", affected_assets=["user-a"])
    assert engine.state.findings["F-1"].priority > 45
    engine.ingest_finding(
        {"id": "F-1", "title": "Reclassified observation", "severity": "low"}, override=True
    )
    assert engine.state.findings["F-1"].title == "Reclassified observation"
    assert engine.query_findings(severity="high")[0].id == "F-2"


def test_engine_handles_decision_edges_and_closure_guards(tmp_path: Path) -> None:
    engine = WorkflowEngine(tmp_path)
    engine.start()
    with pytest.raises(WorkflowError, match="required actions"):
        engine.close()
    with pytest.raises(WorkflowError, match="Unknown workflow action"):
        engine.decide("missing", "accept")
    with pytest.raises(WorkflowError, match="Finding id"):
        engine.ingest_finding({"id": "", "title": ""})

    engine.complete_action("authorize-scope")
    engine.complete_action("run-discovery")
    engine.ingest_finding({"id": "F-1", "title": "Suspected issue", "severity": "low"})
    with pytest.raises(WorkflowError, match="Invalid finding transition"):
        engine.transition_finding("F-1", "closed")
    with pytest.raises(WorkflowError, match="verification evidence"):
        engine.transition_finding("F-1", "validated")
        engine.transition_finding("F-1", "exploited")
        engine.transition_finding("F-1", "mitigated")
        engine.transition_finding("F-1", "closed")

    malformed = {"workflow_id": "x", "phase": "unknown"}
    with pytest.raises(WorkflowError, match="Unknown workflow phase"):
        WorkflowEngine.from_state(tmp_path, malformed)


def test_canonical_finding_adapter_is_report_safe() -> None:
    record = finding_from_document(
        {
            "id": "ADAF-1",
            "title": "Test finding",
            "severity": "high",
            "confidence": "confirmed",
            "impact": "impact",
            "remediation": "fix",
            "source_capability": "ldap-enum",
            "evidence": [{"artifact": "x.json", "pointer": "/a"}],
            "affected_assets": ["user-a"],
            "attack_techniques": ["T1003"],
        }
    )
    assert record.source == "ldap-enum"
    assert record.evidence[0]["artifact"] == "x.json"
    assert record.priority == 77


def test_engine_rejects_invalid_inputs_and_covers_recovery_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    invalid = FindingRecord("F", "bad", severity="not-a-severity", confidence="not-confidence")
    invalid.normalize()
    assert invalid.severity == "info"
    assert invalid.confidence == "unknown"

    engine = WorkflowEngine(tmp_path)
    with pytest.raises(WorkflowError, match="Step name"):
        engine.complete_step("")
    with pytest.raises(WorkflowError, match="Unknown workflow phase"):
        engine.complete_step("step", phase="not-a-phase")
    with pytest.raises(WorkflowError, match="Unknown finding status"):
        engine.ingest_finding({"id": "F", "title": "bad", "status": "invalid"})
    engine.ingest_finding({"id": "F", "title": "one"})
    engine.ingest_finding({"id": "F", "title": "two", "related_findings": ["other"]})
    assert engine.state.findings["F"].created_at
    with pytest.raises(WorkflowError, match="cannot be enriched"):
        engine.enrich_finding("F", id="nope")
    with pytest.raises(WorkflowError, match="Unknown finding"):
        engine.enrich_finding("missing", confidence="confirmed")
    with pytest.raises(WorkflowError, match="Unknown finding status"):
        engine.transition_finding("F", "invalid")  # type: ignore[arg-type]
    with pytest.raises(WorkflowError, match="not a decision"):
        engine.decide("validate:F", "accept")
    with pytest.raises(WorkflowError, match="Unknown workflow action"):
        engine.complete_action("missing")
    engine.state.pending_actions["validate:F"].blocked = True
    with pytest.raises(WorkflowError, match="blocked"):
        engine.complete_action("validate:F")
    with pytest.raises(WorkflowError, match="Unknown finding"):
        engine.transition_finding("missing", "validated")

    payload = engine.state.document()
    restored = WorkflowEngine.from_state(tmp_path, payload)
    assert restored.state.workflow_id == engine.state.workflow_id
    with pytest.raises(WorkflowError, match="Invalid workflow state"):
        WorkflowEngine.from_state(tmp_path, {"phase": "scoping"})

    original_replace = __import__("adaf_attack.core.workflow_engine", fromlist=["os"]).os.replace
    monkeypatch.setattr(
        "adaf_attack.core.workflow_engine.os.replace",
        lambda *_args: (_ for _ in ()).throw(OSError("replace failed")),
    )
    with pytest.raises(OSError, match="replace failed"):
        engine.persist()
    monkeypatch.setattr("adaf_attack.core.workflow_engine.os.replace", original_replace)

    clean = WorkflowEngine(tmp_path / "clean")
    clean.start()
    clean.complete_action("authorize-scope")
    clean.complete_action("run-discovery")
    clean.close(archive=True)
    assert clean.state.status == "archived"

    blocked = WorkflowEngine(tmp_path / "blocked")
    blocked.start()
    blocked.complete_action("authorize-scope")
    blocked.complete_action("run-discovery")
    blocked.ingest_finding({"id": "F", "title": "open"})
    blocked.complete_action("validate:F")
    with pytest.raises(WorkflowError, match="findings remain open"):
        blocked.close()


def test_low_finding_has_no_dead_end_and_guidance_is_queryable(tmp_path: Path) -> None:
    engine = WorkflowEngine(tmp_path)
    engine.start()
    engine.complete_action("authorize-scope")
    engine.complete_action("run-discovery")
    engine.ingest_finding({"id": "F-LOW", "title": "Minor control gap", "severity": "low"})
    engine.transition_finding("F-LOW", "validated")
    assert engine.recommendations()[0].id == "decision:F-LOW"
    engine.decide("decision:F-LOW", "mitigate", rationale="Owner approved remediation")
    assert engine.recommendations()[0].id == "response:F-LOW"
    engine.complete_action("response:F-LOW")
    assert engine.recommendations()[0].id == "verify:F-LOW"
    engine.complete_action("verify:F-LOW")
    engine.transition_finding("F-LOW", "closed", evidence={"artifact": "verify.json"})
    assert engine.recommendations()[0].id == "generate-report"
    guidance = engine.guidance()
    assert isinstance(guidance, WorkflowGuidance)
    assert guidance.next_action_id == "generate-report"
    assert guidance.open_finding_ids == ()
    assert guidance.document()["next_action_id"] == "generate-report"
    engine.complete_action("generate-report")
    engine.close()
    assert engine.guidance().explanation.startswith("This workflow is finished")


def test_exploited_finding_gets_mitigation_action(tmp_path: Path) -> None:
    engine = WorkflowEngine(tmp_path)
    engine.start()
    engine.complete_action("authorize-scope")
    engine.complete_action("run-discovery")
    engine.ingest_finding({"id": "F-EXP", "title": "Impact path", "severity": "high"})
    engine.transition_finding("F-EXP", "validated")
    engine.decide("decision:F-EXP", "confirm-impact")
    engine.transition_finding("F-EXP", "exploited")
    assert engine.recommendations()[0].id == "mitigate:F-EXP"
    engine.complete_action("mitigate:F-EXP")
    assert engine.state.findings["F-EXP"].status == "mitigated"


def test_guidance_explains_idle_state_and_decision_guard(tmp_path: Path) -> None:
    engine = WorkflowEngine(tmp_path)
    assert engine.guidance().explanation.startswith("No action is currently available")
    engine.start()
    engine.complete_action("authorize-scope")
    engine.complete_action("run-discovery")
    engine.ingest_finding({"id": "F-DEC", "title": "Decision needed"})
    engine.transition_finding("F-DEC", "validated")
    with pytest.raises(WorkflowError, match="requires decide"):
        engine.complete_action("decision:F-DEC")


def test_empty_assessment_records_report_before_closure(tmp_path: Path) -> None:
    engine = WorkflowEngine(tmp_path)
    engine.start()
    engine.complete_action("authorize-scope")
    engine.complete_action("run-discovery")
    engine.close()
    assert engine.state.status == "complete"
    assert "final-report" in engine.state.completed_steps
    assert any(event.event_type == "action.completed" for event in engine.state.audit_log)


def test_action_completion_advances_finding_and_exposes_transport_snapshot(tmp_path: Path) -> None:
    engine = WorkflowEngine(tmp_path)
    engine.start()
    engine.complete_action("authorize-scope")
    engine.complete_action("run-discovery")
    engine.ingest_finding({"id": "F-ACTION", "title": "Action-driven finding"})

    engine.complete_action("validate:F-ACTION")
    assert engine.state.findings["F-ACTION"].status == "validated"
    assert engine.state.phase == "validation"
    snapshot = engine.snapshot()
    assert snapshot["guidance"]["next_action_id"] == "decision:F-ACTION"
    assert snapshot["recommendations"]
    assert engine.query_actions(kind="decision")[0].id == "decision:F-ACTION"


def test_terminal_state_is_immutable_and_corrupt_disk_state_fails_closed(tmp_path: Path) -> None:
    engine = WorkflowEngine(tmp_path)
    engine.start()
    engine.complete_action("authorize-scope")
    engine.complete_action("run-discovery")
    engine.close()
    with pytest.raises(WorkflowError, match="already closed"):
        engine.inject_finding("late observation")

    corrupt = tmp_path / "corrupt"
    corrupt.mkdir()
    (corrupt / "workflow-state.json").write_text("not-json", encoding="utf-8")
    with pytest.raises(WorkflowError, match="Invalid persisted workflow state"):
        WorkflowEngine(corrupt)
    non_object = tmp_path / "non-object"
    non_object.mkdir()
    (non_object / "workflow-state.json").write_text("[]", encoding="utf-8")
    with pytest.raises(WorkflowError, match="expected an object"):
        WorkflowEngine(non_object)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"workflow_id": "x", "mode": "invalid"}, "Unknown workflow mode"),
        ({"workflow_id": "x", "status": "invalid"}, "Unknown workflow status"),
        (
            {"workflow_id": "x", "findings": {"F": {"id": "F", "title": "x", "status": "bad"}}},
            "Unknown finding status",
        ),
        (
            {
                "workflow_id": "x",
                "pending_actions": {
                    "a": {
                        "id": "a",
                        "title": "x",
                        "description": "x",
                        "phase": "bad",
                    }
                },
            },
            "Unknown action phase",
        ),
        (
            {
                "workflow_id": "x",
                "pending_actions": {
                    "a": {
                        "id": "a",
                        "title": "x",
                        "description": "x",
                        "phase": "scoping",
                        "kind": "bad",
                    }
                },
            },
            "Unknown action kind",
        ),
    ],
)
def test_state_decoder_rejects_invalid_enums(
    tmp_path: Path, payload: dict[str, object], message: str
) -> None:
    with pytest.raises(WorkflowError, match=message):
        WorkflowEngine.from_state(tmp_path, payload)


def test_rule_registration_rejects_invalid_derived_actions(tmp_path: Path) -> None:
    engine = WorkflowEngine(tmp_path)
    engine.register_rule(lambda _state: [])

    with pytest.raises(WorkflowError, match="Workflow rules must return"):
        engine.register_rule(lambda _state: [object()])  # type: ignore[list-item]

    phase_engine = WorkflowEngine(tmp_path / "phase")
    with pytest.raises(WorkflowError, match="Unknown workflow phase"):
        phase_engine.register_rule(
            lambda _state: [WorkflowAction("invalid-phase", "Invalid", "Invalid", "not-a-phase")]
        )


def test_query_and_audit_filters_cover_transport_views(tmp_path: Path) -> None:
    engine = WorkflowEngine(tmp_path)
    engine.start()
    engine.state.pending_actions["custom"] = WorkflowAction(
        "custom", "Custom", "Custom action", "discovery", "recommended"
    )
    engine.complete_action("custom")
    assert engine.query_actions(phase="discovery", include_completed=True)[0].id == "custom"
    assert engine.query_actions(phase="missing") == []
    assert engine.audit_history()
    assert engine.audit_history(event_type="workflow.started")
    assert engine.audit_history(event_type="missing") == []


def test_validation_and_close_guards_cover_unauthorized_and_unstarted_paths(
    tmp_path: Path,
) -> None:
    engine = WorkflowEngine(tmp_path)
    engine.ingest_finding({"id": "F-GUARD", "title": "Guard"})
    with pytest.raises(WorkflowError, match="authorized scope"):
        engine.transition_finding("F-GUARD", "validated")

    no_scope = WorkflowEngine(tmp_path / "no-scope")
    no_scope.state.pending_actions = {}
    with pytest.raises(WorkflowError, match="scope authorization"):
        no_scope.close()

    no_discovery = WorkflowEngine(tmp_path / "no-discovery")
    no_discovery.state.pending_actions = {}
    no_discovery.state.completed_steps = ["scope-authorized"]
    with pytest.raises(WorkflowError, match="discovery completes"):
        no_discovery.close()


def test_recommendations_prioritize_highest_risk_finding_and_explain_unlocks(
    tmp_path: Path,
) -> None:
    engine = WorkflowEngine(tmp_path)
    engine.start()
    assert engine.guidance().next_action_id == "authorize-scope"
    assert engine.query_actions(include_completed=True)[0].unlock_conditions

    engine.complete_action("authorize-scope")
    engine.complete_action("run-discovery")
    engine.ingest_finding({"id": "F-LOW", "title": "Minor gap", "severity": "low"})
    engine.ingest_finding(
        {"id": "F-CRITICAL", "title": "Domain compromise path", "severity": "critical"}
    )
    assert engine.recommendations()[0].id == "validate:F-CRITICAL"
    assert engine.recommendations()[0].priority == 40


def test_report_unlock_uses_newly_derived_actions(tmp_path: Path) -> None:
    engine = WorkflowEngine(tmp_path)
    engine.start()
    engine.complete_action("authorize-scope")
    engine.complete_action("run-discovery")
    engine.ingest_finding({"id": "F-1", "title": "Issue", "severity": "medium"})
    engine.complete_action("validate:F-1")
    engine.decide("decision:F-1", "mitigate")
    engine.complete_action("response:F-1")
    engine.complete_action("verify:F-1")
    engine.transition_finding("F-1", "closed", evidence={"artifact": "verified.json"})
    assert engine.recommendations()[0].id == "generate-report"
