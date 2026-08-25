"""Offline tests for the unified operator tool services."""

from __future__ import annotations

import json
from pathlib import Path

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.tooling import (
    detection_export,
    graph_explorer,
    import_evidence,
    scope_manifest_summary,
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
    findings.write_text(
        json.dumps({"findings": [{"id": "F-1", "title": "Issue", "severity": "high"}]}),
        encoding="utf-8",
    )

    imported = import_evidence(session, source)
    verified = verify_finding(session, "F-1", evidence=["ldap.json"])

    assert Path(imported["destination"]).is_file()
    assert verified["finding"]["status"] == "remediated"
    assert json.loads(findings.read_text(encoding="utf-8"))["findings"][0]["status"] == "remediated"


def test_detection_export_and_scope_manifest(tmp_path: Path) -> None:
    session = tmp_path / "session"
    session.mkdir()
    (session / "graph.json").write_text(
        json.dumps({"nodes": [], "edges": [{"kind": "DCSync"}, {"kind": "WriteGPO"}]}),
        encoding="utf-8",
    )
    manifest = tmp_path / "scope.json"
    manifest.write_text(
        json.dumps({"domain": "corp.example", "snapshot": "clean", "fixtures": ["baseline"]}),
        encoding="utf-8",
    )

    detections = detection_export(session)
    scope = scope_manifest_summary(manifest)

    assert detections["count"] == 2
    assert scope["reserved_domain"] is True
    assert scope["ready_for_review"] is True


def test_import_evidence_error_branches(tmp_path: Path) -> None:
    import pytest

    from adaf_attack.core.tooling import import_evidence

    missing_session = tmp_path / "no-session"
    with pytest.raises(FileNotFoundError, match="Session directory"):
        import_evidence(missing_session, tmp_path / "x.json")

    session = tmp_path / "session"
    session.mkdir()
    with pytest.raises(FileNotFoundError, match="Evidence file"):
        import_evidence(session, tmp_path / "missing.json")

    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        import_evidence(session, bad)

    good = tmp_path / "good.json"
    good.write_text("{}", encoding="utf-8")
    import_evidence(session, good)
    with pytest.raises(FileExistsError):
        import_evidence(session, good)
    again = import_evidence(session, good, overwrite=True)
    assert again["ok"] is True


def test_verify_finding_error_branches(tmp_path: Path) -> None:
    import pytest

    from adaf_attack.core.tooling import verify_finding

    session = tmp_path / "session"
    session.mkdir()
    findings = session / "findings.json"
    findings.write_text(
        json.dumps(
            {
                "findings": [
                    "not-a-dict",
                    {"title": "T", "severity": "low"},
                    {"id": "F-2", "title": "Other"},
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(KeyError, match="F-9"):
        verify_finding(session, "F-9")
    verified = verify_finding(session, "F-2")
    assert verified["finding"]["id"] == "F-2"

    findings.write_text(json.dumps({"findings": None}), encoding="utf-8")
    with pytest.raises(ValueError, match="findings list"):
        verify_finding(session, "F-2")


def test_scope_summary_branches(tmp_path: Path) -> None:
    import pytest

    from adaf_attack.core.tooling import scope_summary

    plan = tmp_path / "plan.yaml"
    plan.write_text(
        "engagement_id: E1\n"
        "target:\n"
        "  domain: corp.example\n"
        "  dc_ip: 10.0.0.10\n"
        "allowed_targets: 10.0.0.10\n"
        "allowed_capabilities: ldap-enum\n"
        "phases:\n"
        "  - name: recon\n"
        "    capabilities: [ldap-enum]\n",
        encoding="utf-8",
    )
    summary = scope_summary(plan)
    assert summary["engagement_id"] == "E1"
    assert summary["allowed_targets"] == ["10.0.0.10"]
    assert summary["allowed_capabilities"] == ["ldap-enum"]
    assert summary["phase_count"] == 1

    scalar = tmp_path / "scalar.yaml"
    scalar.write_text("just-a-string\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mapping"):
        scope_summary(scalar)


def test_detection_export_skips_malformed_and_duplicate_edges(tmp_path: Path) -> None:
    session = tmp_path / "session"
    session.mkdir()
    (session / "graph.json").write_text(
        json.dumps(
            {
                "nodes": [],
                "edges": [
                    "not-a-dict",
                    {"kind": "DCSync"},
                    {"kind": "DCSync"},
                    {"kind": "UnknownKind"},
                ],
            }
        ),
        encoding="utf-8",
    )
    detections = detection_export(session)
    assert detections["count"] == 1
    assert detections["rules"][0]["source_relation"] == "DCSync"


def test_scope_manifest_summary_rejects_non_mapping(tmp_path: Path) -> None:
    import pytest

    from adaf_attack.core.tooling import scope_manifest_summary

    manifest = tmp_path / "scope.json"
    manifest.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        scope_manifest_summary(manifest)
