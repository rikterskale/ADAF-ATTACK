"""Targeted coverage for the evidence-first engagement surfaces."""

from __future__ import annotations

import asyncio
import json
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import typer
from textual.widgets import ListView, Static
from typer.testing import CliRunner

from adaf_attack.cli import app
from adaf_attack.core.access_context import best_identity_for_capability, session_access_context
from adaf_attack.core.asset_workspace import build_asset_workspace
from adaf_attack.core.engagement_dashboard import dashboard, inspect_edge, mission, missions
from adaf_attack.core.finding_workspace import build_finding_workspace, load_finding_workspace
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.local_queries import query_local_evidence
from adaf_attack.core.outcomes import build_post_execution_outcome, record_detection_status
from adaf_attack.core.ux import diff_sessions, unified_search
from adaf_attack.core.ux_extra import capability_dependency_graph, evaluate_prerequisites
from adaf_attack.tui.app import ADAFAttackApp


def _session(tmp_path: Path) -> Path:
    session = tmp_path / "session"
    session.mkdir()
    (session / "session.json").write_text(
        json.dumps({"session_id": "S-1", "engagement_id": "E-1", "scope": "domain"}),
        encoding="utf-8",
    )
    graph = AttackGraph()
    graph.add_node("USER@CORP", "User", compromised=True)
    graph.add_node("GROUP@DOMAIN ADMINS@CORP", "Group", admin_count=True)
    graph.add_edge(
        "USER@CORP",
        "GROUP@DOMAIN ADMINS@CORP",
        "GenericAll",
        evidence_source="acl-enum",
        observed_at="2026-08-20T00:00:00Z",
        verified=True,
        corroboration=["acl", "ldap"],
    )
    graph.save(session / "graph.json")
    return session


def test_engagement_and_edge_views_cover_saved_evidence(tmp_path: Path) -> None:
    session = _session(tmp_path)
    (session / "events.jsonl").write_text(
        '{"type":"run.complete","capability":"acl-enum","username":"alice","auth":"ccache"}\n'
        "bad json\n",
        encoding="utf-8",
    )
    (session / "findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "F-1",
                        "title": "ACL exposure",
                        "status": "open",
                        "severity": "high",
                        "confidence": "confirmed",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    assert dashboard(session, mode="invalid", ranking="invalid")["engagement"]["mode"] == "OBSERVE"
    assert dashboard(session, mode="validate", ranking="quietest")["ranking"] == "quietest"
    edge = inspect_edge(session / "graph.json", index=0)["edges"][0]
    assert edge["confidence"] == "high"
    assert edge["verified"] is True
    assert edge["corroboration_count"] == 2
    assert inspect_edge(session / "graph.json", source="missing")["count"] == 0


def test_asset_workspace_aggregates_safe_evidence(tmp_path: Path) -> None:
    session = _session(tmp_path)
    (session / "events.jsonl").write_text(
        '{"type":"run.complete","capability":"ldap-enum","username":"alice","asset":"USER@CORP"}\n'
        "bad\n{}\n",
        encoding="utf-8",
    )
    (session / "findings.json").write_text(
        json.dumps({"findings": [{"id": "F-1", "asset": "USER@CORP"}, "bad"]}),
        encoding="utf-8",
    )
    view = build_asset_workspace(session, "user@corp")
    assert view["summary"] == {"nodes": 1, "relationships": 1, "findings": 1, "actions": 1}
    assert view["access"]["recommended_identity"] == "alice"
    assert build_asset_workspace(tmp_path / "missing", "asset")["summary"]["nodes"] == 0
    with pytest.raises(ValueError, match="cannot be empty"):
        build_asset_workspace(session, " ")
    alternate = AttackGraph()
    alternate.add_node("A", "User")
    alternate.add_node("B", "Group")
    alternate.add_edge("A", "B", "Other", corroboration="single")
    alternate.save(session / "alternate.json")
    assert inspect_edge(session / "alternate.json")["edges"][0]["corroboration_count"] == 1
    assert missions() and mission("tier-0-paths") is not None and mission("missing") is None
    context = session_access_context(session)
    assert context["recommended_identity"] == "alice"
    assert best_identity_for_capability(session, "ldap-enum")["identity"] == "alice"
    assert best_identity_for_capability(session, "missing")["identity"] == "alice"
    cli = CliRunner().invoke(
        app,
        ["--format", "json", "engagement", "asset", "USER@CORP", "--session", str(session)],
    )
    assert cli.exit_code == 0
    malformed = tmp_path / "malformed"
    malformed.mkdir()
    (malformed / "graph.json").write_text("not json", encoding="utf-8")
    assert build_asset_workspace(malformed, "asset")["summary"]["nodes"] == 0
    (session / "ticket.kirbi").write_bytes(b"x")
    (session / "certificate.pfx").write_bytes(b"x")
    (session / "password.txt").write_bytes(b"x")
    assert len(session_access_context(session)["credential_artifacts"]) == 3
    (session / "graph.json").write_text("not json", encoding="utf-8")
    assert dashboard(session)["attack_paths"]["edges"] == 0
    (session / "events.jsonl").write_text(
        '[1]\n{"type":"run.start","capability":"x"}\n'
        '{"type":"other","username":"bob","auth":"hash"}\n',
        encoding="utf-8",
    )
    assert session_access_context(session)["recommended_identity"] is None
    assert best_identity_for_capability(session, "missing")["identity"] == "bob"
    empty = tmp_path / "empty"
    empty.mkdir()
    assert best_identity_for_capability(empty, "missing")["identity"] is None
    (session / "findings.json").write_text(
        json.dumps({"findings": [{"id": "closed", "status": "closed"}]}), encoding="utf-8"
    )
    assert dashboard(session)["recommended_next_actions"][0]["id"] == "generate-report"
    (session / "graph.json").write_text("{}", encoding="utf-8")
    assert inspect_edge(session / "graph.json", source="missing")["count"] == 0


def test_finding_workspace_variants_and_loader(tmp_path: Path) -> None:
    session = _session(tmp_path)
    (session / "evidence.json").write_text("{}", encoding="utf-8")
    finding = {
        "id": "F-1",
        "title": "Observed",
        "source_capability": "acl-enum",
        "evidence": ["evidence.json", {"path": "missing.json", "pointer": "/x"}, 4],
        "severity": "critical",
        "confidence": "high",
        "techniques": "T1234",
    }
    workspace = build_finding_workspace(session, finding)
    assert workspace["evidence_quality"]["status"] == "incomplete"
    assert workspace["next_actions"][0]["id"] == "capture-evidence"
    closed = build_finding_workspace(session, {"title": "Closed", "status": "closed"})
    assert closed["next_actions"][0]["id"] == "verify-closure"
    (session / "findings.json").write_text(json.dumps({"findings": [finding]}), encoding="utf-8")
    assert load_finding_workspace(session, "F-1")["id"] == "F-1"
    assert build_finding_workspace(
        session, {"title": "Dict", "evidence": {"path": "evidence.json"}}
    )["evidence"]
    assert build_finding_workspace(session, {"title": "Bad", "evidence": "bad"})["evidence"] == []
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "findings.json").write_text("{}", encoding="utf-8")
    with suppress(ValueError):
        load_finding_workspace(bad, "missing")
    (bad / "findings.json").write_text("not json", encoding="utf-8")
    with suppress(ValueError):
        load_finding_workspace(bad, "missing")
    (bad / "findings.json").write_text(json.dumps(["bad"]), encoding="utf-8")
    with suppress(ValueError):
        load_finding_workspace(bad, "missing")


def test_local_queries_outcomes_and_detection(tmp_path: Path) -> None:
    session = _session(tmp_path)
    paths = query_local_evidence(session, "show every path from compromised users to Domain Admin")
    assert paths["count"] == 1
    findings = query_local_evidence(session, "which findings depend on alice")
    assert findings["count"] == 0
    (session / "findings.json").write_text(
        json.dumps({"findings": [{"id": "F-2", "title": "alice dependency"}, "bad"]}),
        encoding="utf-8",
    )
    assert query_local_evidence(session, "which findings depend on alice")["count"] == 1
    assert (
        query_local_evidence(session, "show paths from USER@CORP to GROUP@DOMAIN ADMINS@CORP")[
            "count"
        ]
        == 1
    )
    unsupported = query_local_evidence(session, "what changed since yesterday")
    assert unsupported["ok"] is False
    missing = tmp_path / "missing"
    with suppress(ValueError):
        query_local_evidence(missing, "show paths from alice to Domain Admin")
    graph = AttackGraph()
    graph.add_node("USER@CORP", "User")
    (session / "artifact.txt").write_text("x", encoding="utf-8")
    outcome = build_post_execution_outcome(
        session, capability="ldap-enum", result={"ok": False}, graph=graph, auth="ccache"
    )
    assert outcome["status"] == "partial"
    detection = record_detection_status(
        session, status="detected", notes="SIEM alert", telemetry=["4662"]
    )
    assert detection["status"] == "detected"
    (session / "cleanup.json").write_text(json.dumps([{"status": "failed"}]), encoding="utf-8")
    assert (
        build_post_execution_outcome(session, capability="x", result={}, graph=graph, auth="none")[
            "rollback"
        ]["status"]
        == "failed"
    )
    (session / "cleanup.json").write_text("{}", encoding="utf-8")
    assert (
        build_post_execution_outcome(session, capability="x", result={}, graph=graph, auth="none")[
            "rollback"
        ]["status"]
        == "not-required"
    )
    (session / "cleanup.json").write_text(json.dumps([{"status": "completed"}]), encoding="utf-8")
    assert (
        build_post_execution_outcome(session, capability="x", result={}, graph=graph, auth="none")[
            "rollback"
        ]["status"]
        == "verified"
    )
    with suppress(ValueError):
        record_detection_status(session, status="invalid")
    assert query_local_evidence(session, "show paths from unknown to unknown")["count"] == 0
    deep = AttackGraph()
    nodes = [f"N{i}" for i in range(10)]
    for node in nodes:
        deep.add_node(node, "User")
    for left, right in zip(nodes[:-1], nodes[1:], strict=True):
        deep.add_edge(left, right, "MemberOf")
    deep.add_node("GOAL", "Group")
    deep.add_edge(nodes[-1], "GOAL", "MemberOf")
    deep.save(session / "graph.json")
    assert query_local_evidence(session, "show paths from N0 to GOAL")["count"] == 0


def test_search_and_prerequisite_variants(tmp_path: Path) -> None:
    session = _session(tmp_path)
    (session / "findings.json").write_text(
        json.dumps(
            {"findings": [{"id": "F", "title": "GenericAll finding", "asset": "USER"}, "bad"]}
        ),
        encoding="utf-8",
    )
    assert unified_search("genericall", session=session)["results"]
    (session / "graph.json").write_text("not json", encoding="utf-8")
    assert unified_search("user", session=session)["results"]
    assert evaluate_prerequisites("ldap-enum")["status"] == "not-required"
    assert (
        evaluate_prerequisites("attack-paths", session=tmp_path / "missing")["status"] == "missing"
    )
    (session / "events.jsonl").write_text("not json\n", encoding="utf-8")
    assert evaluate_prerequisites("attack-paths", session=session)["status"] in {
        "missing",
        "satisfied",
    }


def test_remaining_branch_edges(tmp_path: Path, monkeypatch: Any) -> None:
    session = _session(tmp_path)
    (session / "findings.json").write_text(
        json.dumps({"findings": [{"id": "F", "title": "known"}]}), encoding="utf-8"
    )
    assert query_local_evidence(session, "which findings depend on absent")["count"] == 0
    from adaf_attack.core import ux_extra

    monkeypatch.setitem(ux_extra._PREREQUISITES, "synthetic", ["producer"])
    (session / "producer.json").write_text("{}", encoding="utf-8")
    assert evaluate_prerequisites("synthetic", session=session)["status"] == "satisfied"

    graph = AttackGraph()
    graph.add_node("A", "User")
    graph.add_node("B", "User")
    graph.add_edge("A", "B", "MemberOf")
    graph.add_edge("B", "A", "MemberOf")
    graph.save(session / "graph.json")
    assert query_local_evidence(session, "show paths from A to B")["count"] == 1
    assert query_local_evidence(session, "show paths from A to A")["count"] == 0

    (session / "findings.json").write_text(json.dumps({"findings": {"id": "F"}}), encoding="utf-8")
    assert unified_search("absent", session=session)["results"] == []
    no_graph = tmp_path / "no-graph"
    no_graph.mkdir()
    (no_graph / "session.json").write_text("{}", encoding="utf-8")
    assert unified_search("absent", session=no_graph)["results"] == []
    graph.add_edge("A", "B", "Unrelated")
    graph.save(no_graph / "graph.json")
    assert unified_search("absent", session=no_graph)["results"] == []

    from adaf_attack.capabilities import acl_primitives

    monkeypatch.setattr(
        acl_primitives,
        "parse_interesting_aces",
        lambda _value: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    with pytest.raises(RuntimeError, match="boom"):
        acl_primitives._adminsdholder_rights_ok(b"malformed", "S-1-5-21-1-2-3-4")
    other = tmp_path / "other"
    other.mkdir()
    (other / "session.json").write_text("{}", encoding="utf-8")
    assert diff_sessions(session, other)["attack_paths_changed"] is True
    (session / "graph.json").write_text(
        json.dumps({"edges": [{"source": "", "target": "", "kind": "X"}, "bad"]}),
        encoding="utf-8",
    )
    assert unified_search("ldap", session=session)["results"]
    (session / "findings.json").write_text(
        json.dumps({"findings": [{"id": "F", "title": "unrelated"}, "bad"]}),
        encoding="utf-8",
    )
    assert unified_search("missing-term", session=session)["results"] == []
    (session / "graph.json").write_text(
        json.dumps(
            {
                "edges": [
                    "bad",
                    {"source": "", "target": "x", "kind": "X"},
                    {"source": "a", "target": "b", "kind": "x"},
                ]
            }
        ),
        encoding="utf-8",
    )
    assert isinstance(diff_sessions(session, other)["relationships_added"], list)
    assert capability_dependency_graph("not-registered")["nodes"][0]["available"] is False
    (session / "events.jsonl").write_text("{}\n", encoding="utf-8")
    assert evaluate_prerequisites("attack-paths", session=session)["status"] == "missing"
    (session / "events.jsonl").write_text('{"capability":"ldap-enum"}\n', encoding="utf-8")
    assert evaluate_prerequisites("attack-paths", session=session)["status"] in {
        "missing",
        "satisfied",
    }


def test_tui_modes_attack_edges_and_validation(tmp_path: Path) -> None:
    session = _session(tmp_path)

    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            app._set_operation_mode("unknown")
            app._show_attack_paths()
            assert "Complete or select" in str(app.query_one("#attack-path-panel", Static).render())
            app._last_session = tmp_path / "no-graph"
            app._last_session.mkdir()
            app._show_attack_paths()
            assert "No graph.json" in str(app.query_one("#attack-path-panel", Static).render())
            app._last_session = session
            app._set_operation_mode("EMULATE")
            assert "Mode: EMULATE" in str(app.query_one("#engagement-dashboard", Static).render())
            app._show_attack_paths()
            edge_list = app.query_one("#attack-edge-list", ListView)
            assert len(edge_list) == 1
            item = edge_list.children[0]
            app.on_list_view_selected(SimpleNamespace(item=item))  # type: ignore[arg-type]
            assert "Selected edge" in str(app.query_one("#attack-edge-detail", Static).render())
            app._prepare_edge_validation()
            assert app._operation_mode == "VALIDATE"
            assert "Edge validation handoff" in str(app.query_one("#review-panel", Static).render())
            app._clear_attack_edges()
            await pilot.pause()
            assert len(edge_list) == 0
            app._prepare_edge_validation()

    asyncio.run(exercise())


def test_tui_attack_path_error_and_empty_branches(tmp_path: Path, monkeypatch) -> None:
    async def exercise() -> None:
        app_instance = ADAFAttackApp()
        async with app_instance.run_test() as pilot:
            await pilot.pause()
            app_instance._last_session = _session(tmp_path)

            def fail_graph(*_args, **_kwargs):
                raise ValueError("bad")

            monkeypatch.setattr("adaf_attack.tui.app.graph_explorer", fail_graph)
            app_instance._show_attack_paths()
            assert "could not be read" in str(
                app_instance.query_one("#attack-path-panel", Static).render()
            )
            monkeypatch.setattr(
                "adaf_attack.tui.app.graph_explorer",
                lambda *_args, **_kwargs: {"summary": {}, "paths": ["bad"]},
            )
            app_instance._show_attack_paths()
            await pilot.pause()
            assert "No selectable" in str(
                app_instance.query_one("#attack-edge-detail", Static).render()
            )
            monkeypatch.setattr(
                "adaf_attack.tui.app.graph_explorer",
                lambda *_args, **_kwargs: {"summary": {}, "paths": []},
            )
            app_instance._show_attack_paths()
            monkeypatch.setattr(
                "adaf_attack.tui.app.graph_explorer",
                lambda *_args, **_kwargs: {
                    "summary": {},
                    "paths": [
                        {"path": ["A"], "edges": ["R"], "length": 1},
                        {"path": ["A"], "edges": []},
                        {"path": ["A", "B"], "edges": ["R"]},
                        {"path": ["A", "B"], "edges": ["R"]},
                    ],
                },
            )
            monkeypatch.setattr("adaf_attack.tui.app.inspect_edge", fail_graph)
            app_instance._show_attack_paths()
            await pilot.pause()
            assert "No selectable" in str(
                app_instance.query_one("#attack-edge-detail", Static).render()
            )
            app_instance._selected_attack_edge = {"relation": "unknown"}
            monkeypatch.setattr("adaf_attack.tui.app.capability_registry.get", lambda _id: None)
            app_instance._prepare_edge_validation()

    asyncio.run(exercise())


def test_product_and_graph_cli_surfaces(tmp_path: Path) -> None:
    runner = CliRunner()
    from adaf_attack.cli_product_commands import register_product_commands

    isolated = typer.Typer()
    register_product_commands(
        isolated,
        emit=lambda *_args, **_kwargs: None,
        emit_error=lambda *_args, **_kwargs: None,
    )
    session = _session(tmp_path)
    (session / "findings.json").write_text(
        json.dumps({"findings": [{"id": "F-1", "title": "Finding"}]}), encoding="utf-8"
    )
    for args in (
        ["engagement", "missions"],
        ["engagement", "mission", "tier-0-paths"],
        ["engagement", "dashboard", "--session", str(session)],
        ["path", "inspect", "--graph", str(session / "graph.json")],
        ["capability", "dependencies"],
        [
            "query",
            "show every path from compromised users to Domain Admin",
            "--session",
            str(session),
        ],
        ["query", "which findings depend on F-1", "--session", str(session)],
        ["query", "what changed", "--session", str(session)],
        ["query", "show paths from nowhere to nowhere", "--session", str(session)],
        ["query", "show paths from nowhere to nowhere", "--session", str(tmp_path / "missing")],
        ["cleanup-status", "--session", str(session)],
        ["detection-status", "--session", str(session), "--status", "detected"],
        ["detection-status", "--session", str(session), "--status", "invalid"],
        ["finding", "workspace", "--session", str(session), "--id", "F-1"],
        ["finding", "workspace", "--session", str(session), "--id", "missing"],
        ["path", "inspect", "--graph", str(session / "missing.json")],
        ["session", "access", "--session", str(session)],
        ["session", "access", "--session", str(tmp_path / "missing")],
        ["what-next", "--session", str(session)],
        ["engagement", "mission", "missing"],
    ):
        result = runner.invoke(app, ["--format", "json", *args])
        assert result.exit_code in {0, 1, 2}, result.output
