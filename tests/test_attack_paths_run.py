"""Behavioral tests."""

from __future__ import annotations

import json
from pathlib import Path

from adaf_attack.capabilities.attack_paths import AttackPaths
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def test_attack_paths_loads_graph_ranks_findings_and_writes_artifacts(tmp_path: Path) -> None:
    source = AttackGraph()
    source.add_node("USER@ALICE@CORP.TEST", "User", sam="alice")
    source.add_node("GROUP@DOMAIN ADMINS@CORP.TEST", "Group", sam="Domain Admins")
    source.add_edge("USER@ALICE@CORP.TEST", "GROUP@DOMAIN ADMINS@CORP.TEST", "GenericAll")
    graph_path = tmp_path / "source-graph.json"
    source.save(graph_path)
    session = Session(tmp_path / "sessions")
    graph = AttackGraph()

    result = AttackPaths().run(
        Target(domain="corp.test", dc_ip="192.0.2.10"),
        session,
        graph,
        graph_path=graph_path,
        start="alice",
    )

    assert result["loaded_from"] == str(graph_path)
    assert result["count"] >= 1
    assert result["paths"][0]["start"] == "USER@ALICE@CORP.TEST"
    assert (
        json.loads(session.path("ranked-paths.json").read_text(encoding="utf-8"))["count"]
        == result["count"]
    )
    interesting = json.loads(session.path("interesting.json").read_text(encoding="utf-8"))
    assert interesting["top_paths"][0]["start"] == "USER@ALICE@CORP.TEST"
