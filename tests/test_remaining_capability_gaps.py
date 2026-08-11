"""Offline coverage for final capability containment branches."""

from __future__ import annotations

from pathlib import Path

import pytest

from adaf_attack.capabilities import bloodhound_export, campaign_analysis, esc_chain
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def _target() -> Target:
    return Target(domain="corp.test", dc_ip="192.0.2.10", username="alice")


def test_bloodhound_hydration_contains_malformed_session_json(tmp_path: Path) -> None:
    session = Session(tmp_path)
    session.path("graph.json").write_text("{broken", encoding="utf-8")
    assert bloodhound_export._hydrate_graph_from_session(session, AttackGraph()) is False


def test_blast_radius_skips_a_seen_non_self_cycle(tmp_path: Path) -> None:
    graph = AttackGraph()
    graph.add_node("USER@ALICE@CORP", "User", sam="alice")
    graph.add_node("GROUP@OPS@CORP", "Group")
    graph.add_edge("USER@ALICE@CORP", "GROUP@OPS@CORP", "MemberOf")
    graph.add_edge("GROUP@OPS@CORP", "USER@ALICE@CORP", "MemberOf")
    result = campaign_analysis.BlastRadius().run(_target(), Session(tmp_path), graph, start="alice")
    assert result["reachable_nodes"] == 2


def test_esc_chain_reports_missing_or_unexploitable_prior_session(tmp_path: Path) -> None:
    session = Session(tmp_path / "current")
    with pytest.raises(RuntimeError, match="not found"):
        esc_chain.EscChain().run(
            _target(), session, AttackGraph(), adcs_session=tmp_path / "missing"
        )
    prior = tmp_path / "prior"
    prior.mkdir()
    (prior / "adcs-enum.json").write_text('{"templates":[]}', encoding="utf-8")
    with pytest.raises(RuntimeError, match="No exploitable"):
        esc_chain.EscChain().run(_target(), session, AttackGraph(), adcs_session=prior)
