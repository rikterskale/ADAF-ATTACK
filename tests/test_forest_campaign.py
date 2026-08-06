import json

from adaf_attack.core.forest_campaign import compose_forest_campaign
from adaf_attack.core.graph import AttackGraph


def test_forest_campaign_merges_trusts(tmp_path) -> None:
    session = tmp_path / "s"
    session.mkdir()
    (session / "session.json").write_text(json.dumps({"domain": "corp.local"}), encoding="utf-8")
    graph = AttackGraph()
    graph.add_node("DOMAIN@CORP.LOCAL", "Domain")
    graph.add_node("DOMAIN@CHILD.LOCAL", "Domain")
    graph.add_edge("DOMAIN@CORP.LOCAL", "DOMAIN@CHILD.LOCAL", "TrustedBy")
    graph.save(session / "graph.json")
    result = compose_forest_campaign([session])
    assert result["domains"] == ["corp.local"]
    assert len(result["trust_transitions"]) == 1
