"""Tests for polished product-level surfaces."""

from __future__ import annotations

import json
from pathlib import Path

from adaf_attack.core.product import (
    command_center,
    confidence_report,
    deliverables_manifest,
    evidence_impact_map,
    executive_story,
    product_templates,
    zero_noise_investigation,
)


def make_session(tmp_path: Path) -> Path:
    session = tmp_path / "session"
    session.mkdir()
    (session / "session.json").write_text(json.dumps({"session_id": "s1"}), encoding="utf-8")
    (session / "findings.json").write_text(json.dumps({"findings": [
        {"id": "F-1", "title": "Critical path", "severity": "critical", "confidence": "high", "evidence": ["acl.json"]},
    ]}), encoding="utf-8")
    (session / "graph.json").write_text(json.dumps({"nodes": [{"id": "USER@alice"}], "edges": []}), encoding="utf-8")
    return session


def test_product_views_are_evidence_first(tmp_path: Path) -> None:
    session = make_session(tmp_path)
    center = command_center(session)
    impact = evidence_impact_map(session)
    investigation = zero_noise_investigation(session)
    story = executive_story(session)
    confidence = confidence_report(session)

    assert center["mode"] == "review-and-report"
    assert impact["map"][0]["finding_id"] == "F-1"
    assert investigation["network_contact"] is False
    assert "highest observed severity was critical" in story["narrative"]
    assert confidence["quality"] == "strong"


def test_templates_and_deliverables_manifest(tmp_path: Path) -> None:
    session = make_session(tmp_path)
    manifest = deliverables_manifest(session)

    assert product_templates()
    assert manifest["ready"] is False
    assert "reports/executive.html" in manifest["expected"]
