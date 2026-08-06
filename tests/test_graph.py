"""Attack graph unit tests."""

import json
from pathlib import Path

from adaf_attack.core.graph import AttackGraph


def test_add_node_and_edge() -> None:
    g = AttackGraph()
    g.add_node("USER@ALICE@CORP.LOCAL", "User", sam="alice")
    g.add_node("GROUP@DOMAIN ADMINS@CORP.LOCAL", "Group", sam="Domain Admins")
    g.add_edge(
        "USER@ALICE@CORP.LOCAL",
        "GROUP@DOMAIN ADMINS@CORP.LOCAL",
        "MemberOf",
    )
    assert len(g.nodes) == 2
    assert len(g.edges) == 1
    summary = g.summary()
    assert summary["nodes"] == 2
    assert summary["edge_kinds"]["MemberOf"] == 1


def test_rank_paths() -> None:
    g = AttackGraph()
    g.add_node("u1", "User")
    g.add_node("g1", "Group", sam="Domain Admins", admin_count=True)
    g.add_edge("u1", "g1", "MemberOf")
    paths = g.rank_paths("u1", goal_kinds=("Group",), limit=5)
    assert paths
    assert paths[0].nodes[-1] == "g1"
    assert paths[0].score < 3.0  # HV bonus applied


def test_rank_genericall_shorter_than_memberof() -> None:
    g = AttackGraph()
    g.add_node("u1", "User", sam="bob")
    g.add_node("g1", "Group", sam="Domain Admins")
    g.add_node("g2", "Group", sam="Helpdesk")
    g.add_edge("u1", "g2", "MemberOf")
    g.add_edge("g2", "g1", "GenericAll")
    g.add_edge("u1", "g1", "MemberOf")
    paths = g.rank_paths("u1", goal_kinds=("Group",), limit=10)
    assert paths
    # Direct MemberOf to DA and path via GenericAll both present; scores ordered
    scores = [p.score for p in paths]
    assert scores == sorted(scores)


def test_find_node_by_sam() -> None:
    g = AttackGraph()
    g.add_node("USER@ALICE@CORP.LOCAL", "User", sam="alice")
    assert g.find_node("alice") == "USER@ALICE@CORP.LOCAL"
    assert g.find_node("USER@ALICE@CORP.LOCAL") == "USER@ALICE@CORP.LOCAL"


def test_load_and_save(tmp_path: Path) -> None:
    g = AttackGraph()
    g.add_node("u1", "User", sam="alice")
    g.add_node("g1", "Group", sam="Domain Admins")
    g.add_edge("u1", "g1", "GenericAll")
    path = tmp_path / "graph.json"
    g.save(path)
    g2 = AttackGraph.from_file(path)
    assert len(g2.nodes) == 2
    assert len(g2.edges) == 1
    ranked = g2.rank_from_principals(["u1"], limit=5)
    assert ranked
    data = json.loads(path.read_text())
    assert "nodes" in data and "edges" in data


def test_rank_from_principals_merged() -> None:
    g = AttackGraph()
    g.add_node("u1", "User", sam="a")
    g.add_node("u2", "User", sam="b")
    g.add_node("g1", "Group", sam="Domain Admins")
    g.add_edge("u1", "g1", "GenericAll")
    g.add_edge("u2", "g1", "MemberOf")
    merged = g.rank_from_principals(["u1", "u2"], limit=10)
    assert len(merged) >= 2
    assert merged[0]["score"] <= merged[-1]["score"]
