"""Attack graph unit tests."""

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
