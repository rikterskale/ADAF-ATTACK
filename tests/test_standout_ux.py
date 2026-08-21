"""Tests for evidence-first standout UX services."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.standout_ux import (
    collaboration_summary,
    copilot_recommendations,
    evidence_cockpit,
    session_timeline,
    what_if_graph,
)


def _session(tmp_path: Path) -> Path:
    session = tmp_path / "session"
    session.mkdir()
    (session / "session.json").write_text(json.dumps({"session_id": "s1"}), encoding="utf-8")
    (session / "findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "F-1",
                        "title": "Issue",
                        "severity": "high",
                        "status": "open",
                        "owner": "alice",
                        "triage_note": "review",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (session / "events.jsonl").write_text(
        json.dumps(
            {"ts": "2026-01-01T00:00:00Z", "type": "run.complete", "capability": "ldap-enum"}
        )
        + "\n",
        encoding="utf-8",
    )
    graph = AttackGraph()
    graph.add_node("USER@alice", "user")
    graph.add_node("GROUP@admins", "group")
    graph.add_edge("USER@alice", "GROUP@admins", "MemberOf")
    graph.save(session / "graph.json")
    return session


def test_cockpit_timeline_copilot_and_collaboration(tmp_path: Path) -> None:
    session = _session(tmp_path)

    cockpit = evidence_cockpit(session)
    timeline = session_timeline(session)
    copilot = copilot_recommendations(session)
    collaboration = collaboration_summary(session)

    assert cockpit["offline"] is True
    assert cockpit["priority_focus"][0]["id"] == "F-1"
    assert timeline["replayable"] is True
    assert copilot["recommendations"][0]["id"] == "triage-open-findings"
    assert collaboration["owners"] == {"alice": 1}


def test_what_if_does_not_modify_source_graph(tmp_path: Path) -> None:
    session = _session(tmp_path)
    graph_path = session / "graph.json"
    before = graph_path.read_text(encoding="utf-8")

    result = what_if_graph(graph_path, remove_relation="MemberOf")

    assert len(result["removed_edges"]) == 1
    assert result["writes_target"] is False
    assert graph_path.read_text(encoding="utf-8") == before


def test_what_if_graph_error_and_malformed_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"nodes": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="edges list"):
        what_if_graph(bad, remove_relation="MemberOf")

    session = _session(tmp_path)
    graph_path = session / "graph.json"
    document = json.loads(graph_path.read_text(encoding="utf-8"))
    document["edges"].append("not-a-dict")
    graph_path.write_text(json.dumps(document), encoding="utf-8")
    # A non-dict edge is preserved but cannot be re-loaded by the explorer,
    # so stub the explorer to observe filtering behavior only.
    import adaf_attack.core.standout_ux as sx

    monkeypatch.setattr(
        sx,
        "graph_explorer",
        lambda path, *, limit=10: {"summary": {}, "path_count": 0},
    )
    result = sx.what_if_graph(graph_path, remove_relation="MemberOf")
    assert result["ok"] is True
    assert len(result["removed_edges"]) == 1


def test_session_timeline_skips_malformed_lines(tmp_path: Path) -> None:
    session = _session(tmp_path)
    events = session / "events.jsonl"
    events.write_text(
        "not-json\n" + json.dumps({"time": "t2", "event": "x", "error": "boom"}) + "\n" + "[1]\n",
        encoding="utf-8",
    )
    timeline = session_timeline(session, limit=5)
    assert timeline["count"] == 1
    assert timeline["events"][0]["status"] == "error"


def test_copilot_recommendations_branches(tmp_path: Path) -> None:
    session = _session(tmp_path)
    # Open findings + graph edges both present -> two recommendations.
    copilot = copilot_recommendations(session)
    assert [r["id"] for r in copilot["recommendations"]][:2] == [
        "triage-open-findings",
        "rank-evidence-paths",
    ]

    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "findings.json").write_text(json.dumps({"findings": []}), encoding="utf-8")
    fallback = copilot_recommendations(empty)
    assert fallback["recommendations"][0]["id"] == "generate-report"


def test_session_timeline_without_events_file(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    timeline = session_timeline(empty)
    assert timeline["count"] == 0
    assert timeline["events"] == []
