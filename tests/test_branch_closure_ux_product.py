"""Branch-closure tests for product, novice, ux, and runner edge paths."""

from __future__ import annotations

import json
from pathlib import Path

from adaf_attack.core.novice import explain_finding_payload
from adaf_attack.core.product import confidence_report
from adaf_attack.core.runner import RunError  # noqa: F401
from adaf_attack.core.ux import diff_sessions


def test_confidence_report_skips_malformed_and_flags_weak(tmp_path: Path) -> None:
    session = tmp_path / "session"
    session.mkdir()
    (session / "findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    "not-a-dict",
                    {"id": "F-1", "confidence": "high"},
                    {"id": "F-2", "evidence": ["a.txt"]},
                    {"title": "NoConf", "confidence": "low"},
                ]
            }
        ),
        encoding="utf-8",
    )
    report = confidence_report(session)
    assert report["confidence_counts"] == {"high": 1, "medium": 1, "low": 1}
    assert report["ok"] is True
    assert report["needs_more_evidence"] == ["NoConf"]

    (session / "findings.json").write_text(json.dumps({"findings": None}), encoding="utf-8")
    empty = confidence_report(session)
    assert empty["confidence_counts"] == {}


def test_explain_finding_payload_evidence_shapes() -> None:
    as_string = explain_finding_payload(
        {"id": "F-1", "title": "T", "severity": "HIGH", "evidence": "ev.json"}
    )
    assert as_string["evidence"] == ["ev.json"]

    as_bad = explain_finding_payload({"id": "F-2", "evidence": {"oops": True}})
    assert as_bad["evidence"] == []

    defaults = explain_finding_payload({})
    assert defaults["id"] == "finding"
    assert defaults["severity"] == "unknown"


def test_diff_sessions_tolerates_malformed_findings(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "findings.json").write_text(json.dumps({"findings": "bad"}), encoding="utf-8")
    (b / "findings.json").write_text(
        json.dumps({"findings": ["x", {"no-id": True}, {"id": "F-1"}]}),
        encoding="utf-8",
    )
    diff = diff_sessions(a, b)
    assert diff["findings_added"] == ["F-1"]
