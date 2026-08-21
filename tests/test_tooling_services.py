"""Offline tests for the unified operator tool services."""

from __future__ import annotations

import json
from pathlib import Path

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.tooling import (
    detection_export,
    graph_explorer,
    import_evidence,
    lab_manifest_summary,
    verify_finding,
)


def test_graph_explorer_reports_relations_and_paths(tmp_path: Path) -> None:
    graph = AttackGraph()
    graph.add_node("USER@alice", "user")
    graph.add_node("GROUP@admins", "group")
    graph.add_edge("USER@alice", "GROUP@admins", "MemberOf")
    graph_path = tmp_path / "graph.json"
    graph.save(graph_path)

    payload = graph_explorer(graph_path, start="alice")

    assert payload["offline"] is True
    assert payload["relation_counts"] == {"MemberOf": 1}
    assert payload["summary"]["nodes"] == 2


def test_import_evidence_and_verify_finding(tmp_path: Path) -> None:
    session = tmp_path / "session"
    session.mkdir()
    source = tmp_path / "ldap.json"
    source.write_text(json.dumps({"objects": []}), encoding="utf-8")
    findings = session / "findings.json"
    findings.write_text(json.dumps({"findings": [{"id": "F-1", "title": "Issue", "severity": "high"}]}), encoding="utf-8")

    imported = import_evidence(session, source)
    verified = verify_finding(session, "F-1", evidence=["ldap.json"])

    assert Path(imported["destination"]).is_file()
    assert verified["finding"]["status"] == "remediated"
    assert json.loads(findings.read_text(encoding="utf-8"))["findings"][0]["status"] == "remediated"


def test_detection_export_and_lab_manifest(tmp_path: Path) -> None:
    session = tmp_path / "session"
    session.mkdir()
    (session / "graph.json").write_text(
        json.dumps({"nodes": [], "edges": [{"kind": "DCSync"}, {"kind": "WriteGPO"}]}),
        encoding="utf-8",
    )
    manifest = tmp_path / "lab.json"
    manifest.write_text(
        json.dumps({"domain": "lab.example", "snapshot": "clean", "fixtures": ["baseline"]}),
        encoding="utf-8",
    )

    detections = detection_export(session)
    lab = lab_manifest_summary(manifest)

    assert detections["count"] == 2
    assert lab["reserved_domain"] is True
    assert lab["ready_for_review"] is True
