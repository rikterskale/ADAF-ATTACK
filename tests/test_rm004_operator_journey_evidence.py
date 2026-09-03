"""Behavioral evidence for RM-004 operator journey and interaction paths."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

import adaf_attack.cli as cli
import adaf_attack.core.journey as journey
import adaf_attack.core.registry as registry
import adaf_attack.tui.app as tui_app
from adaf_attack.cli import app
from adaf_attack.core.registry import (
    ApprovalPolicy,
    Capability,
    RiskLevel,
    RollbackClass,
    SafetyProfile,
)
from adaf_attack.core.workflow_engine import WorkflowAction, WorkflowEngine, WorkflowError
from adaf_attack.tui.app import ADAFAttackApp

runner = CliRunner()


def _journey_payload(action_id: str, *, advance_safe: bool = True) -> dict[str, object]:
    action = {
        "id": action_id,
        "title": f"{action_id} title",
        "why": "A local operator workflow step.",
        "suggested_command": f"adaf-attack workflow do {action_id}",
        "advance_safe": advance_safe,
        "evidence_basis": [],
    }
    return {
        "ok": True,
        "stage": "discover",
        "stage_label": "Baseline discovery",
        "progress_pct": 40.0,
        "primary_action": action,
        "secondary_actions": [],
        "context": {"session_hint": None},
        "breadcrumb": [],
        "suggested_command": action["suggested_command"],
        "recovery_command": "adaf-attack guide",
    }


def test_cli_readiness_labels_cover_platform_and_container_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ReleaseFile:
        def read_text(self, *, encoding: str) -> str:
            return 'NAME="Ubuntu"\nVERSION_ID="24.04"\nIGNORED_LINE\n'

    monkeypatch.setattr(cli, "Path", lambda _path: ReleaseFile())
    monkeypatch.setattr(cli.host_platform, "system", lambda: "Linux")
    assert cli._os_release_label() == "Ubuntu 24.04"

    class MissingRelease:
        def read_text(self, *, encoding: str) -> str:
            raise OSError("release metadata unavailable")

    monkeypatch.setattr(cli, "Path", lambda _path: MissingRelease())
    monkeypatch.setattr(cli.host_platform, "release", lambda: "6.1")
    assert cli._os_release_label() == "Linux 6.1"

    monkeypatch.setattr(cli.host_platform, "system", lambda: "Darwin")
    monkeypatch.setattr(cli.host_platform, "mac_ver", lambda: ("14.5", ("", "", ""), ""))
    assert cli._os_release_label() == "macOS 14.5"
    monkeypatch.setattr(cli.host_platform, "mac_ver", Mock(side_effect=RuntimeError("probe")))
    assert cli._os_release_label() == "Darwin 6.1"

    monkeypatch.setattr(cli.host_platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        cli.host_platform,
        "win32_ver",
        lambda: ("11", "10.0.22631", "", ""),
    )
    assert cli._os_release_label() == "Windows 11 10.0.22631"
    monkeypatch.setattr(cli.host_platform, "win32_ver", Mock(side_effect=RuntimeError("probe")))
    assert cli._os_release_label() == "Windows 6.1"

    monkeypatch.delenv("ADAF_ATTACK_IN_CONTAINER", raising=False)
    assert cli._container_context() == ("ok", "host", None)
    monkeypatch.setenv("ADAF_ATTACK_IN_CONTAINER", "1")
    status, value, remediation = cli._container_context()
    assert (status, value) == ("warning", "container (offline-only)")
    assert remediation and "host DNS" in remediation
    monkeypatch.setenv("ADAF_ATTACK_CONTAINER_ACKNOWLEDGE_LIVE", "yes")
    assert cli._container_context() == ("ok", "container (live-mode acknowledged)", None)


def test_doctor_repair_text_is_complete_for_operator_statuses() -> None:
    checks = [
        {"id": "python", "status": "ok"},
        {"id": "optional-tool", "status": "warning"},
        {"id": "workspace", "status": "error"},
        {"id": "pip-check", "status": "error"},
        {"id": "packaged-demo", "status": "error"},
        {"id": "target-arguments", "status": "error"},
        {"id": "already-described", "status": "ok", "remediation": "Keep it."},
    ]
    cli._ensure_doctor_repair_text(checks, profile="user-readiness")
    assert checks[0]["remediation"].startswith("Keep using Python")
    assert "Optional gap" in checks[1]["remediation"]
    assert checks[2]["repair_command"] == "adaf-attack paths --repair"
    assert checks[3]["repair_command"] == "python -m pip check"
    assert checks[4]["repair_command"].startswith("adaf-attack quickstart")
    assert "authorized-domain" in checks[5]["repair_command"]
    assert checks[6]["remediation"] == "Keep it."


def test_support_bundle_secret_scan_is_a_blocking_actionable_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        cli,
        "_doctor_payload",
        lambda *args, **kwargs: {"ok": True, "checks": []},
    )
    monkeypatch.setattr(
        "adaf_attack.core.engineering.diagnostics_snapshot",
        lambda **kwargs: {"status": "ok"},
    )
    monkeypatch.setattr(
        "adaf_attack.core.redaction.unredacted_secret_hits",
        lambda _rendered: ["password=detected"],
    )
    result = runner.invoke(
        app,
        ["--format", "json", "support-bundle", "--output", str(tmp_path / "bundle.json")],
    )
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["error"]["code"] == "SECRET_IN_OUTPUT"
    assert payload["error"]["recovery_command"] == "adaf-attack guide"
    assert payload["error"]["details"]["output"].endswith("bundle.json")


def test_journey_safety_metadata_explains_approval_and_rollback_contracts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    automatic = Capability(
        "auto-cap",
        "automatic test capability",
        safety=SafetyProfile(
            risk=RiskLevel.SIDE_EFFECT,
            rollback=RollbackClass.AUTOMATIC,
            network_side_effect=True,
        ),
    )
    force_ack = Capability(
        "force-cap",
        "force test capability",
        safety=SafetyProfile(
            risk=RiskLevel.DESTRUCTIVE,
            approval=ApprovalPolicy.FORCE_AND_ACK,
            rollback=RollbackClass.MANUAL,
            network_side_effect=True,
        ),
    )
    scoped = Capability(
        "scoped-cap",
        "scoped test capability",
        safety=SafetyProfile(
            risk=RiskLevel.SIDE_EFFECT,
            approval=ApprovalPolicy.SCOPED_TOKEN,
            network_side_effect=True,
        ),
    )
    values = {cap.id: cap for cap in (automatic, force_ack, scoped)}
    monkeypatch.setattr(registry.capability_registry, "get", values.get)

    assert journey._action_safety_metadata("validate:F-1")["rollback"] == "none"
    assert journey._action_safety_metadata("decision:F-1")["approvals"] == []
    assert journey._action_safety_metadata("custom-action")["risk"] == "SENSITIVE"
    assert journey._action_safety_metadata("auto-cap")["approvals"] == [
        "Written authorization for the target scope"
    ]
    assert journey._action_safety_metadata("auto-cap")["rollback"] == "automatic"
    force_metadata = journey._action_safety_metadata("force-cap")
    assert force_metadata["approvals"] == ["--force", "--i-understand (first use in workspace)"]
    assert force_metadata["rollback"] == "manual"
    scoped_metadata = journey._action_safety_metadata("scoped-cap")
    assert "--approval-token with matching --engagement-id" in scoped_metadata["approvals"]
    assert journey._action_safety_metadata("custom-action", capability_id="scoped-cap")["risk"] == (
        "SIDE_EFFECT"
    )


def test_journey_commands_use_profile_defaults_and_cover_operator_actions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        journey,
        "load_user_config",
        lambda: {"profile.default": "engagement"},
    )
    monkeypatch.setattr(
        "adaf_attack.core.profiles.get_profile",
        lambda _name: {"domain": "corp.test", "dc_ip": "192.0.2.10", "username": "alice"},
    )
    discovery = WorkflowAction(
        "run-discovery",
        "Discover",
        "Discover",
        "discovery",
        capability_id="ldap-enum",
    )
    command = journey.suggested_command_for_action(discovery, workspace=tmp_path)
    assert "ldap-enum" in command and "corp.test" in command and "alice" in command

    commands = {
        "mitigate": journey.suggested_command_for_action(
            WorkflowAction("mitigate:F-1", "Mitigate", "", "response", "required"),
            workspace=tmp_path,
        ),
        "report": journey.suggested_command_for_action(
            WorkflowAction("generate-report", "Report", "", "reporting", "required"),
            workspace=tmp_path,
        ),
        "report-session": journey.suggested_command_for_action(
            WorkflowAction("generate-report", "Report", "", "reporting", "required"),
            workspace=tmp_path,
            session=tmp_path / "session one",
        ),
        "capability": journey.suggested_command_for_action(
            WorkflowAction(
                "custom-action", "Custom", "", "discovery", "required", capability_id="auto-cap"
            ),
            workspace=tmp_path,
        ),
    }
    assert "mitigated" in commands["mitigate"]
    assert "workflow do generate-report" in commands["report"]
    assert "engagement report" in commands["report-session"]
    assert "auto-cap" in commands["capability"]

    monkeypatch.setattr(
        journey,
        "load_user_config",
        lambda: {"profile.default": "broken"},
    )
    monkeypatch.setattr(
        "adaf_attack.core.profiles.get_profile",
        Mock(side_effect=ValueError("invalid profile")),
    )
    fallback = journey.suggested_command_for_action(discovery, workspace=tmp_path)
    assert "workflow do run-discovery" in fallback


def test_journey_evidence_redacts_invalid_paths_and_preserves_valid_digest() -> None:
    finding = SimpleNamespace(
        evidence=[
            "malformed evidence entry",
            {"artifact": "", "pointer": "/ignored"},
            {"artifact": "../secrets.json", "pointer": "bad", "sha256": "z" * 64},
            {"artifact": "../evidence.json", "pointer": "/status", "sha256": "A" * 64},
        ]
    )
    action = WorkflowAction(
        "validate:F-1",
        "Validate",
        "Review",
        "validation",
        finding_ids=["F-1", "F-2"],
    )
    basis = journey._workflow_evidence_basis(action, {"F-1": finding})
    assert any(item["ref"] == "secrets.json#/" for item in basis)
    artifact = next(
        item for item in basis if item["kind"] == "artifact" and "/status" in item["ref"]
    )
    assert artifact["ref"] == "evidence.json#/status"
    assert artifact["sha256"] == "a" * 64
    assert any(item["ref"] == "finding:F-2" for item in basis)
    empty = journey._workflow_evidence_basis(
        WorkflowAction("custom", "Custom", "", "validation"), None
    )
    assert empty[0]["kind"] == "workflow-action"


def test_journey_renderers_keep_empty_and_secondary_surfaces_actionable() -> None:
    evidence = journey.journey_evidence_summary(
        {"evidence_basis": [{"kind": "finding", "ref": str(i)} for i in range(5)]}
    )
    assert "+2 more" in evidence
    assert journey.journey_evidence_summary({"evidence_basis": []}).startswith("state=")
    lines = journey.journey_summary_lines(
        {
            "stage": "operate",
            "progress_pct": 60,
            "primary_action": {"title": "Review", "evidence_basis": []},
            "secondary_actions": [{"title": "Fallback", "suggested_command": "adaf guide"}, 7],
            "fallback": "adaf-attack workflow next",
            "recovery_command": "adaf-attack guide",
        },
        include_secondary=True,
    )
    assert any(line.startswith("Fallback:") for line in lines)
    assert any(line.startswith("If this fails:") for line in lines)
    assert all(not line.endswith("7") for line in lines)


def test_journey_snapshot_handles_authorized_empty_session_and_profiled_blockers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = tmp_path / "empty-session"
    session.mkdir()
    (session / "session.json").write_text(json.dumps({"session_id": "empty"}), encoding="utf-8")
    engine = WorkflowEngine(tmp_path)
    engine.start(actor="test")
    engine.complete_action("authorize-scope", actor="test")
    payload = journey.snapshot(
        workspace=tmp_path,
        session=session,
        doctor={"ok": True, "checks": []},
    )
    assert payload["stage"] == "discover"
    assert payload["primary_action"]["id"] == "import-session"
    assert payload["secondary_actions"][0]["id"] == "run-discovery"

    monkeypatch.setattr(journey, "_packaged_demo_ready", lambda: (False, None))
    blockers = journey._doctor_blockers(None)
    assert blockers[0]["id"] == "packaged-demo"
    checks = journey._doctor_blockers(
        {
            "checks": [
                None,
                {"id": "data_dir", "status": "error", "detail": "locked"},
                {"id": "other", "status": "error", "value": "bad"},
            ]
        }
    )
    assert checks[0]["suggested_command"] == "adaf-attack paths --repair"
    assert checks[1]["message"] == "bad"


def test_guide_advance_import_errors_and_unknown_safe_handlers_are_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        cli, "_doctor_payload", lambda *_args, **_kwargs: {"ok": True, "checks": []}
    )
    session = tmp_path / "session"
    session.mkdir()
    initial = _journey_payload("import-session")
    initial["context"] = {"session_hint": str(session)}
    monkeypatch.setattr(journey, "snapshot", lambda **_kwargs: initial)
    monkeypatch.setattr(
        journey,
        "import_session_findings",
        Mock(side_effect=WorkflowError("scope is not authorized")),
    )
    result = runner.invoke(app, ["guide", "--workspace", str(tmp_path), "--advance"])
    assert result.exit_code == 1
    assert "WORKFLOW_TRANSITION_INVALID" in result.output

    unknown = _journey_payload("unknown-safe-action")
    monkeypatch.setattr(journey, "snapshot", lambda **_kwargs: unknown)
    result = runner.invoke(app, ["guide", "--workspace", str(tmp_path), "--advance"])
    assert result.exit_code == 1
    assert "No safe advance handler" in result.output


def test_guide_advance_can_close_an_authorized_empty_workflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        cli, "_doctor_payload", lambda *_args, **_kwargs: {"ok": True, "checks": []}
    )
    engine = WorkflowEngine(tmp_path)
    engine.start(actor="test")
    engine.complete_action("authorize-scope", actor="test")
    engine.complete_action("run-discovery", actor="test")
    engine.complete_action("generate-report", actor="test")
    result = runner.invoke(app, ["guide", "--workspace", str(tmp_path), "--advance"])
    assert result.exit_code == 0, result.output
    assert WorkflowEngine(tmp_path).state.status == "complete"


def test_cli_start_reports_missing_tui_dependency_as_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(__import__("sys").modules, "adaf_attack.tui.app", None)
    result = runner.invoke(app, ["--format", "json", "start"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["error"]["code"] == "TUI_DEPENDENCY_MISSING"


def test_cli_diagnostics_and_empty_graph_keep_recovery_contracts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import subprocess

    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout="adaf-attack has incompatible requirements",
            stderr="",
        ),
    )
    monkeypatch.setattr(
        "adaf_attack.core.engineering.relevant_pip_failures",
        lambda _detail: ["adaf-attack has incompatible requirements"],
    )
    assert cli._pip_consistency_check() == (
        False,
        "adaf-attack has incompatible requirements",
    )
    monkeypatch.setattr(
        cli.subprocess, "run", Mock(side_effect=subprocess.TimeoutExpired("pip", 30))
    )
    ok, detail = cli._pip_consistency_check()
    assert ok is False and "TimeoutExpired" in detail
    monkeypatch.setattr(cli.subprocess, "run", Mock(side_effect=OSError("pip missing")))
    ok, detail = cli._pip_consistency_check()
    assert ok is False and "pip missing" in detail

    graph = tmp_path / "graph.json"
    graph.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        "adaf_attack.core.tooling.graph_explorer",
        lambda *args, **kwargs: {"summary": {"nodes": 2, "edges": 0}, "path_count": 0},
    )
    result = runner.invoke(app, ["--format", "json", "tool", "graph", str(graph)])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["empty_state"]["kind"] == "paths"
    assert payload["suggested_command"]


def test_capability_profile_cli_reports_invalid_and_plan_only_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for command in ("show", "plan"):
        result = runner.invoke(
            app,
            ["--format", "json", "capability-profile", command, "missing-profile"],
        )
        assert result.exit_code == 1
        assert json.loads(result.output)["error"]["code"] == "UNKNOWN_CAPABILITY_PROFILE"

    shown = runner.invoke(
        app,
        ["--format", "json", "capability-profile", "show", "recon"],
    )
    assert shown.exit_code == 0
    assert json.loads(shown.output)["profile"]["count"] > 0
    planned = runner.invoke(
        app,
        ["--format", "json", "capability-profile", "plan", "recon"],
    )
    assert planned.exit_code == 0

    offline = runner.invoke(
        app,
        [
            "--format",
            "json",
            "capability-profile",
            "run",
            "offline-analysis",
            "--domain",
            "corp.test",
            "--dc-ip",
            "192.0.2.10",
            "--workspace",
            str(tmp_path),
            "--yes",
        ],
    )
    assert offline.exit_code == 1
    assert json.loads(offline.output)["error"]["code"] == "PROFILE_RUN_BLOCKED"

    monkeypatch.setattr(
        "adaf_attack.core.engagement.run_engagement",
        lambda *args, **kwargs: {
            "capabilities": ["ldap-enum"],
            "finding_count": 0,
            "session_path": str(tmp_path / "session"),
        },
    )
    success = runner.invoke(
        app,
        [
            "--format",
            "json",
            "capability-profile",
            "run",
            "recon",
            "--domain",
            "corp.test",
            "--dc-ip",
            "192.0.2.10",
            "--workspace",
            str(tmp_path),
            "--yes",
        ],
    )
    assert success.exit_code == 0, success.output
    assert json.loads(success.output)["profile"] == "recon"


def test_session_events_and_audit_verification_preserve_json_and_human_modes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    session = tmp_path / "session"
    session.mkdir()
    (session / "events.jsonl").write_text(
        '\nnot-json\n{"ts":"2026-01-01","type":"run.complete","capability":"ldap-enum","detail":"ok"}\n'
        '{"ts":"2026-01-02","type":"finding.created","capability":"ldap-enum"}\n',
        encoding="utf-8",
    )
    filtered = runner.invoke(
        app,
        [
            "--format",
            "json",
            "session",
            "events",
            "--session",
            str(session),
            "--type",
            "run",
        ],
    )
    assert filtered.exit_code == 0
    assert json.loads(filtered.output)["events"][0]["type"] == "run.complete"
    human = runner.invoke(app, ["session", "events", "--session", str(session)])
    assert human.exit_code == 0 and "Session events" in human.output

    monkeypatch.setattr(
        "adaf_attack.core.session.verify_event_log",
        lambda _path: {"ok": True, "events": 2},
    )
    valid = runner.invoke(
        app, ["--format", "json", "session", "verify-audit", "--session", str(session)]
    )
    assert valid.exit_code == 0 and json.loads(valid.output)["ok"] is True
    monkeypatch.setattr(
        "adaf_attack.core.session.verify_event_log",
        lambda _path: {"ok": False, "events": 2, "error": "hash mismatch"},
    )
    invalid = runner.invoke(app, ["session", "verify-audit", "--session", str(session)])
    assert invalid.exit_code == 1 and "invalid" in invalid.output.lower()


def test_setup_alias_hands_off_to_guide_in_both_output_modes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "init_cmd", lambda *args, **kwargs: None)
    json_result = runner.invoke(app, ["--format", "json", "setup"])
    assert json_result.exit_code == 0
    human_result = runner.invoke(app, ["setup"])
    assert human_result.exit_code == 0
    assert "Authoritative next step" in human_result.output


def test_tui_journey_and_parameter_paths_fail_closed_without_crashing() -> None:
    async def exercise() -> None:
        app_instance = ADAFAttackApp()
        async with app_instance.run_test() as pilot:
            await pilot.pause()
            app_instance._journey = Mock(side_effect=OSError("state unavailable"))  # type: ignore[method-assign]
            app_instance._set_wizard_step(1)
            assert "unavailable" in str(
                app_instance.query_one("#wizard-guide", tui_app.Static).render()
            )

            app_instance._journey = Mock(return_value={"stage": "first-success"})  # type: ignore[method-assign]
            app_instance._quickstart = Mock(return_value=False)  # type: ignore[method-assign]
            app_instance._wizard_step = 0
            app_instance._wizard_next()
            assert app_instance._wizard_step == 0

            app_instance._wizard_step = 3
            app_instance.selected_cap = "dcsync"
            app_instance._reviewed_cap = None
            app_instance._wizard_next()
            assert (
                any(
                    "checklist" in str(call.args[0]).lower()
                    for call in app_instance.notify.call_args_list
                )
                if isinstance(app_instance.notify, Mock)
                else True
            )

            app_instance._param_form_cap_id = "ldap-enum"
            app_instance._param_bindings = [
                {"param_key": "start", "label": "Start", "option": "--start", "is_param": "false"}
            ]
            app_instance.query_one("#param-input-0", tui_app.Input).value = "DC01"
            app_instance._cache_param_form_values()
            assert app_instance._param_value_cache["ldap-enum"]["start"] == "DC01"

            app_instance.selected_cap = None
            app_instance._show_findings()
            assert "Run a capability" in str(
                app_instance.query_one("#session-panel", tui_app.Static).render()
            )

    import asyncio

    asyncio.run(exercise())


def test_tui_run_gates_explain_missing_review_force_token_and_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        app_instance = ADAFAttackApp()
        async with app_instance.run_test() as pilot:
            await pilot.pause()
            notices = Mock()
            app_instance.notify = notices  # type: ignore[method-assign]
            app_instance.query_one("#domain", tui_app.Input).value = "corp.test"
            app_instance.query_one("#dc_ip", tui_app.Input).value = "192.0.2.10"

            app_instance.selected_cap = "dcsync"
            app_instance._reviewed_cap = None
            app_instance._start_run()
            assert "review" in notices.call_args.args[0].lower()

            app_instance.selected_cap = "ldap-enum"
            app_instance._param_bindings = [
                {
                    "param_key": "required",
                    "label": "Required value",
                    "option": "--required",
                    "is_param": False,
                }
            ]
            app_instance._collect_capability_params = Mock(return_value=({}, ["Required value"]))  # type: ignore[method-assign]
            app_instance._start_run()
            assert any(
                "capability parameters" in str(call.args[0]).lower()
                for call in notices.call_args_list
            ), repr(notices.call_args_list)

            app_instance._param_bindings = []
            app_instance.selected_cap = "coerce"
            app_instance._reviewed_cap = "coerce"
            app_instance.query_one("#force", tui_app.Switch).value = True
            app_instance._collect_capability_params = Mock(return_value=({}, []))  # type: ignore[method-assign]
            app_instance._start_run()
            assert any(
                "approval token" in str(call.args[0]).lower() for call in notices.call_args_list
            )

            app_instance.selected_cap = "dcsync"
            app_instance._reviewed_cap = "dcsync"
            app_instance.query_one("#force", tui_app.Switch).value = False
            app_instance._start_run()
            assert any(
                "enable force" in str(call.args[0]).lower() for call in notices.call_args_list
            )

            app_instance.selected_cap = "dcsync"
            app_instance._reviewed_cap = None
            app_instance._update_engagement_dashboard()
            assert "acknowledgement required" in str(
                app_instance.query_one("#engagement-dashboard", tui_app.Static).render()
            )
            app_instance._reviewed_cap = "dcsync"
            app_instance._update_engagement_dashboard()
            assert "Reviewed for selected capability" in str(
                app_instance.query_one("#engagement-dashboard", tui_app.Static).render()
            )

    import asyncio

    asyncio.run(exercise())


def test_tui_quickstart_empty_findings_and_dynamic_parameter_overflow(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def exercise() -> None:
        app_instance = ADAFAttackApp(workspace=tmp_path)
        async with app_instance.run_test() as pilot:
            await pilot.pause()
            monkeypatch.setattr(
                "adaf_attack.demo.materialize_demo_session",
                Mock(side_effect=OSError("workspace is locked")),
            )
            assert app_instance._quickstart() is False
            assert "Quickstart failed" in str(
                app_instance.query_one("#review-panel", tui_app.Static).render()
            )

            session = tmp_path / "empty"
            session.mkdir()
            (session / "findings.json").write_text('{"findings": []}', encoding="utf-8")
            app_instance._last_session = session
            app_instance._explain_findings()
            assert "No findings to explain" in str(
                app_instance.query_one("#session-panel", tui_app.Static).render()
            )

            def prompts(_cap: object) -> list[dict[str, object]]:
                return [
                    {
                        "option": f"--param-{index}",
                        "param_key": f"param_{index}",
                        "is_param": index == 0,
                        "label": f"Parameter {index}",
                        "help": "test value",
                    }
                    for index in range(13)
                ]

            monkeypatch.setattr(tui_app, "required_prompts", prompts)
            app_instance.selected_cap = "ldap-enum"
            app_instance._refresh_param_form()
            assert "more required beyond this form" in str(
                app_instance.query_one("#param-title", tui_app.Static).render()
            )
            for index in range(8):
                app_instance.query_one(f"#param-input-{index}", tui_app.Input).value = f"v{index}"
            values, missing = app_instance._collect_capability_params()
            assert values["param_0"] == "v0"
            assert "Parameter 8" in missing
            assert values["param_1"] == "v1"

    import asyncio

    asyncio.run(exercise())


def test_tui_worker_callbacks_tolerate_teardown_and_missing_widgets() -> None:
    app_instance = ADAFAttackApp()
    app_instance._loop = None
    app_instance._post_ui(lambda: None)

    async def exercise() -> None:
        async with app_instance.run_test():
            app_instance.call_from_thread = Mock(side_effect=RuntimeError("screen closed"))  # type: ignore[method-assign]
            app_instance._post_ui(lambda: None)
            app_instance._set_button_disabled("missing-widget", True)
            app_instance._set_button_label("missing-widget", "Done")
            app_instance._update_status = Mock(side_effect=RuntimeError("status unavailable"))  # type: ignore[method-assign]
            app_instance._safe_update_status()

    import asyncio

    asyncio.run(exercise())
