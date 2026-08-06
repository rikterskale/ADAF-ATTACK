from adaf_attack.capabilities.campaign_analysis import BlastRadius, PurpleFeedback
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def test_blast_radius_finds_admin_path(tmp_path) -> None:
    graph = AttackGraph()
    graph.add_node("USER@ALICE@CORP.LOCAL", "User")
    graph.add_node("GROUP@DOMAIN ADMINS@CORP.LOCAL", "Group", admin_count=True)
    graph.add_edge("USER@ALICE@CORP.LOCAL", "GROUP@DOMAIN ADMINS@CORP.LOCAL", "MemberOf")
    result = BlastRadius().run(Target(domain="corp.local", dc_ip="10.0.0.1"), Session(base_dir=tmp_path), graph, start="alice")
    assert result["high_value_impacts"]


def test_purple_feedback_uses_session_events(tmp_path) -> None:
    session = Session(base_dir=tmp_path)
    session.log("rbcd.complete")
    result = PurpleFeedback().run(Target(domain="corp.local", dc_ip="10.0.0.1"), session, AttackGraph())
    assert result["count"] == 1
