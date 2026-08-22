"""Behavioral tests."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from adaf_attack.cli import app

runner = CliRunner()


def _invoke_json(*args: str) -> dict:
    result = runner.invoke(app, ["--format", "json", *args])
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def _invoke_error(*args: str) -> tuple[int, dict]:
    result = runner.invoke(app, ["--format", "json", *args])
    assert result.exit_code != 0, result.output
    return result.exit_code, json.loads(result.output)


def _patch(monkeypatch, module: str, name: str, payload: dict | Exception) -> None:
    from importlib import import_module

    target = import_module(f"adaf_attack.core.{module}")

    def fake(*args, **kwargs):
        if isinstance(payload, Exception):
            raise payload
        return payload

    monkeypatch.setattr(target, name, fake)


def test_tool_graph_success(tmp_path: Path, monkeypatch) -> None:
    graph = tmp_path / "graph.json"
    graph.write_text("{}", encoding="utf-8")
    _patch(
        monkeypatch,
        "tooling",
        "graph_explorer",
        {"summary": {"nodes": 3, "edges": 4}, "path_count": 2},
    )
    payload = _invoke_json("tool", "graph", str(graph), "--start", "DC01", "--limit", "5")
    assert payload["ok"] is True
    assert payload["path_count"] == 2


def test_tool_graph_missing_file(tmp_path: Path) -> None:
    code, payload = _invoke_error("tool", "graph", str(tmp_path / "nope.json"))
    assert payload["error"]["code"] == "GRAPH_NOT_FOUND"


def test_tool_graph_value_error(tmp_path: Path, monkeypatch) -> None:
    graph = tmp_path / "graph.json"
    graph.write_text("{}", encoding="utf-8")
    _patch(monkeypatch, "tooling", "graph_explorer", ValueError("bad graph"))
    code, payload = _invoke_error("tool", "graph", str(graph))
    assert payload["error"]["code"] == "GRAPH_NOT_FOUND"


def test_tool_evidence_import_success(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "ev.json"
    source.write_text("{}", encoding="utf-8")
    _patch(monkeypatch, "tooling", "import_evidence", {"destination": "/tmp/x"})
    payload = _invoke_json(
        "tool",
        "evidence-import",
        "--session",
        str(tmp_path),
        "--source",
        str(source),
        "--overwrite",
    )
    assert payload["destination"] == "/tmp/x"


def test_tool_evidence_import_failure(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "ev.json"
    source.write_text("{}", encoding="utf-8")
    _patch(monkeypatch, "tooling", "import_evidence", OSError("locked"))
    code, payload = _invoke_error(
        "tool", "evidence-import", "--session", str(tmp_path), "--source", str(source)
    )
    assert payload["error"]["code"] == "INPUT_FILE_INVALID"


def test_tool_scope_success(tmp_path: Path, monkeypatch) -> None:
    plan = tmp_path / "plan.yaml"
    plan.write_text("scope: []", encoding="utf-8")
    _patch(
        monkeypatch,
        "tooling",
        "scope_summary",
        {
            "engagement_id": None,
            "target": "corp.example",
            "allowed_capabilities": ["a"],
            "allowed_targets": [],
            "opsec_profile": "default",
        },
    )
    payload = _invoke_json("tool", "scope", str(plan))
    assert payload["ok"] is True


def test_tool_scope_failure(tmp_path: Path, monkeypatch) -> None:
    plan = tmp_path / "plan.yaml"
    plan.write_text("scope: []", encoding="utf-8")
    _patch(monkeypatch, "tooling", "scope_summary", ValueError("bad yaml"))
    code, payload = _invoke_error("tool", "scope", str(plan))
    assert payload["error"]["code"] == "ENGAGEMENT_PLAN_INVALID"


def test_tool_verify_success(tmp_path: Path, monkeypatch) -> None:
    _patch(monkeypatch, "tooling", "verify_finding", {"status": "remediated"})
    payload = _invoke_json(
        "tool",
        "verify",
        "--session",
        str(tmp_path),
        "--id",
        "F-1",
        "--evidence",
        "a.txt",
        "--evidence",
        "b.txt",
    )
    assert payload["status"] == "remediated"


def test_tool_verify_key_error(tmp_path: Path, monkeypatch) -> None:
    _patch(monkeypatch, "tooling", "verify_finding", KeyError("F-1"))
    code, payload = _invoke_error("tool", "verify", "--session", str(tmp_path), "--id", "F-1")
    assert payload["error"]["code"] == "UNKNOWN_FINDING"


def test_tool_detect_with_output(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "session"
    session.mkdir()
    output = tmp_path / "nested" / "detect.json"
    _patch(monkeypatch, "tooling", "detection_export", {"count": 1})
    payload = _invoke_json("tool", "detect", "--session", str(session), "--output", str(output))
    assert payload["output"] == str(output)
    assert output.is_file()


def test_tool_detect_without_output(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "session"
    session.mkdir()
    _patch(monkeypatch, "tooling", "detection_export", {"count": 0})
    payload = _invoke_json("tool", "detect", "--session", str(session))
    assert "output" not in payload


def test_tool_detect_failure(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "session"
    session.mkdir()
    _patch(monkeypatch, "tooling", "detection_export", OSError("missing"))
    code, payload = _invoke_error("tool", "detect", "--session", str(session))
    assert payload["error"]["code"] == "INPUT_FILE_INVALID"


def test_tool_lab_success(tmp_path: Path, monkeypatch) -> None:
    manifest = tmp_path / "lab.json"
    manifest.write_text("{}", encoding="utf-8")
    _patch(
        monkeypatch,
        "tooling",
        "lab_manifest_summary",
        {
            "domain": "lab.example",
            "reserved_domain": True,
            "snapshot": "snap-1",
            "fixtures": ["f"],
            "ready_for_review": False,
        },
    )
    payload = _invoke_json("tool", "lab", str(manifest))
    assert payload["domain"] == "lab.example"


def test_tool_lab_failure(tmp_path: Path, monkeypatch) -> None:
    manifest = tmp_path / "lab.json"
    manifest.write_text("{}", encoding="utf-8")
    _patch(monkeypatch, "tooling", "lab_manifest_summary", ValueError("bad"))
    code, payload = _invoke_error("tool", "lab", str(manifest))
    assert payload["error"]["code"] == "INPUT_FILE_INVALID"


def test_credential_inventory_success(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "s1"
    session.mkdir()
    _patch(monkeypatch, "workflows", "credential_exposure", {"count": 7})
    payload = _invoke_json("credential-inventory", "--session", str(session))
    assert payload["count"] == 7


def test_credential_inventory_missing_sessions(tmp_path: Path) -> None:
    missing = tmp_path / "gone"
    code, payload = _invoke_error("credential-inventory", "--session", str(missing))
    assert payload["error"]["code"] == "SESSION_NOT_FOUND"
    assert payload["error"].get("details", {}).get("missing") == [str(missing)] or any(
        str(missing) in json.dumps(payload) for _ in [0]
    )


def test_cockpit_success(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "s"
    session.mkdir()
    _patch(
        monkeypatch,
        "standout_ux",
        "evidence_cockpit",
        {"dashboard": {"finding_count": 2}, "graph": {"path_count": 3}, "priority_focus": ["x"]},
    )
    payload = _invoke_json("cockpit", "--session", str(session), "--start", "DC01")
    assert payload["dashboard"]["finding_count"] == 2


def test_cockpit_defaults_and_failure(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "s"
    session.mkdir()
    _patch(
        monkeypatch,
        "standout_ux",
        "evidence_cockpit",
        {"dashboard": {}, "priority_focus": []},
    )
    payload = _invoke_json("cockpit", "--session", str(session))
    assert payload["priority_focus"] == []

    _patch(monkeypatch, "standout_ux", "evidence_cockpit", KeyError("session.json"))
    code, payload = _invoke_error("cockpit", "--session", str(session))
    assert payload["error"]["code"] == "SESSION_NOT_FOUND"


def test_what_if_success(tmp_path: Path, monkeypatch) -> None:
    graph = tmp_path / "g.json"
    graph.write_text("{}", encoding="utf-8")
    _patch(
        monkeypatch,
        "standout_ux",
        "what_if_graph",
        {"removed_edges": [], "paths_before": 5, "paths_after": 4},
    )
    payload = _invoke_json(
        "what-if",
        "--graph",
        str(graph),
        "--remove-relation",
        "MemberOf",
        "--remove-source",
        "a",
        "--remove-target",
        "b",
    )
    assert payload["paths_after"] == 4


def test_what_if_failure(tmp_path: Path, monkeypatch) -> None:
    graph = tmp_path / "g.json"
    graph.write_text("{}", encoding="utf-8")
    _patch(monkeypatch, "standout_ux", "what_if_graph", ValueError("nope"))
    code, payload = _invoke_error("what-if", "--graph", str(graph))
    assert payload["error"]["code"] == "GRAPH_NOT_FOUND"


def test_timeline_success_and_empty(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "s"
    session.mkdir()
    events = [{"time": f"t{i}", "type": "run", "capability": "ldap"} for i in range(12)]
    _patch(monkeypatch, "standout_ux", "session_timeline", {"events": events})
    payload = _invoke_json("timeline", "--session", str(session), "--limit", "10")
    assert len(payload["events"]) == 12

    _patch(monkeypatch, "standout_ux", "session_timeline", {"events": []})
    payload = _invoke_json("timeline", "--session", str(session))
    assert payload["events"] == []


def test_timeline_event_defaults_and_failure(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "s"
    session.mkdir()
    _patch(
        monkeypatch,
        "standout_ux",
        "session_timeline",
        {"events": [{"type": "run"}]},
    )
    payload = _invoke_json("timeline", "--session", str(session))
    assert payload["events"][0]["type"] == "run"

    _patch(monkeypatch, "standout_ux", "session_timeline", OSError("gone"))
    code, payload = _invoke_error("timeline", "--session", str(session))
    assert payload["error"]["code"] == "SESSION_NOT_FOUND"


def test_copilot_success_and_failure(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "s"
    session.mkdir()
    _patch(
        monkeypatch,
        "standout_ux",
        "copilot_recommendations",
        {"recommendations": [{"action": "review", "why": "evidence", "command": "show"}]},
    )
    payload = _invoke_json("copilot", "--session", str(session))
    assert payload["recommendations"][0]["action"] == "review"

    _patch(monkeypatch, "standout_ux", "copilot_recommendations", ValueError("bad"))
    code, payload = _invoke_error("copilot", "--session", str(session))
    assert payload["error"]["code"] == "SESSION_NOT_FOUND"


def test_collaboration_success_and_failure(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "s"
    session.mkdir()
    _patch(
        monkeypatch,
        "standout_ux",
        "collaboration_summary",
        {"owners": ["alice"], "commented_findings": 2},
    )
    payload = _invoke_json("collaboration", "--session", str(session))
    assert payload["owners"] == ["alice"]

    _patch(
        monkeypatch,
        "standout_ux",
        "collaboration_summary",
        {"owners": [], "commented_findings": 0},
    )
    payload = _invoke_json("collaboration", "--session", str(session))
    assert payload["commented_findings"] == 0

    _patch(monkeypatch, "standout_ux", "collaboration_summary", OSError("gone"))
    code, payload = _invoke_error("collaboration", "--session", str(session))
    assert payload["error"]["code"] == "SESSION_NOT_FOUND"


def _product_patch(monkeypatch, name: str, payload: dict | Exception) -> None:
    from adaf_attack.core import product

    def fake(*args, **kwargs):
        if isinstance(payload, Exception):
            raise payload
        return payload

    monkeypatch.setattr(product, name, fake)


def test_product_missing_session_directory(tmp_path: Path) -> None:
    missing = tmp_path / "gone"
    code, payload = _invoke_error("command-center", "--session", str(missing))
    assert payload["error"]["code"] == "SESSION_NOT_FOUND"


def test_command_center_success_and_failure(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "s"
    session.mkdir()
    _product_patch(
        monkeypatch,
        "command_center",
        {
            "headline": "h",
            "mode": "offline",
            "timeline": {"count": 3},
            "deliverables": {"ready": True},
        },
    )
    payload = _invoke_json("command-center", "--session", str(session))
    assert payload["headline"] == "h"

    _product_patch(monkeypatch, "command_center", FileNotFoundError(str(session)))
    code, payload = _invoke_error("command-center", "--session", str(session))
    assert payload["error"]["code"] == "SESSION_NOT_FOUND"


def test_impact_map_success_and_failure(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "s"
    session.mkdir()
    _product_patch(monkeypatch, "evidence_impact_map", {"count": 4})
    payload = _invoke_json("impact-map", "--session", str(session))
    assert payload["count"] == 4

    _product_patch(monkeypatch, "evidence_impact_map", ValueError("bad"))
    code, payload = _invoke_error("impact-map", "--session", str(session))
    assert payload["error"]["code"] == "SESSION_NOT_FOUND"


def test_investigate_success_and_failure(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "s"
    session.mkdir()
    _product_patch(
        monkeypatch,
        "zero_noise_investigation",
        {"artifacts": ["a"], "finding_count": 1},
    )
    payload = _invoke_json("investigate", "--session", str(session))
    assert payload["artifacts"] == ["a"]

    _product_patch(monkeypatch, "zero_noise_investigation", KeyError("x"))
    code, payload = _invoke_error("investigate", "--session", str(session))
    assert payload["error"]["code"] == "SESSION_NOT_FOUND"


def test_story_success_and_failure(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "s"
    session.mkdir()
    _product_patch(monkeypatch, "executive_story", {"narrative": "once upon a time"})
    payload = _invoke_json("story", "--session", str(session))
    assert payload["narrative"] == "once upon a time"

    _product_patch(monkeypatch, "executive_story", OSError("gone"))
    code, payload = _invoke_error("story", "--session", str(session))
    assert payload["error"]["code"] == "SESSION_NOT_FOUND"


def _replay_patch(monkeypatch, payload: dict | Exception) -> None:
    from adaf_attack.core import standout_ux

    def fake(*args, **kwargs):
        if isinstance(payload, Exception):
            raise payload
        return payload

    monkeypatch.setattr(standout_ux, "session_timeline", fake)


def test_replay_with_events(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "s"
    session.mkdir()
    _replay_patch(
        monkeypatch,
        {
            "events": [
                {"time": "t1", "type": "run", "capability": "ldap"},
                {"time": None, "type": "emit"},
                "not-a-dict",
            ]
        },
    )
    payload = _invoke_json("replay", "--session", str(session), "--limit", "5")
    assert len(payload["events"]) == 3


def test_replay_no_events_list(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "s"
    session.mkdir()
    _replay_patch(monkeypatch, {"events": None})
    payload = _invoke_json("replay", "--session", str(session))
    assert payload["events"] is None


def test_replay_empty_events(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "s"
    session.mkdir()
    _replay_patch(monkeypatch, {"events": []})
    payload = _invoke_json("replay", "--session", str(session))
    assert payload["events"] == []


def test_replay_failure(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "s"
    session.mkdir()
    _replay_patch(monkeypatch, OSError("gone"))
    code, payload = _invoke_error("replay", "--session", str(session))
    assert payload["error"]["code"] == "SESSION_NOT_FOUND"


def test_confidence_success_and_failure(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "s"
    session.mkdir()
    _product_patch(
        monkeypatch,
        "confidence_report",
        {"quality": "high", "confidence_counts": {}, "needs_more_evidence": []},
    )
    payload = _invoke_json("confidence", "--session", str(session))
    assert payload["quality"] == "high"

    _product_patch(
        monkeypatch,
        "confidence_report",
        {"quality": "low", "confidence_counts": {}, "needs_more_evidence": ["F-1"]},
    )
    payload = _invoke_json("confidence", "--session", str(session))
    assert payload["needs_more_evidence"] == ["F-1"]

    _product_patch(monkeypatch, "confidence_report", ValueError("bad"))
    code, payload = _invoke_error("confidence", "--session", str(session))
    assert payload["error"]["code"] == "SESSION_NOT_FOUND"


def test_templates_command() -> None:
    result = runner.invoke(app, ["--format", "json", "product-templates"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert isinstance(payload["templates"], list)


def test_deliverables_success_and_failure(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "s"
    session.mkdir()
    _product_patch(
        monkeypatch,
        "deliverables_manifest",
        {"ready": True, "available": ["report"], "generate_command": "make"},
    )
    payload = _invoke_json("deliverables", "--session", str(session))
    assert payload["ready"] is True

    _product_patch(
        monkeypatch,
        "deliverables_manifest",
        {"ready": False, "available": [], "generate_command": "make"},
    )
    payload = _invoke_json("deliverables", "--session", str(session))
    assert payload["ready"] is False

    _product_patch(monkeypatch, "deliverables_manifest", FileNotFoundError(str(session)))
    code, payload = _invoke_error("deliverables", "--session", str(session))
    assert payload["error"]["code"] == "SESSION_NOT_FOUND"
