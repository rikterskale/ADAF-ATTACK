from __future__ import annotations

import base64
import hashlib
import hmac
import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from adaf_attack.core.engagement import load_plan, run_engagement, verify_approval
from adaf_attack.core.findings import findings_from_session, write_findings
from adaf_attack.core.reporting import generate_report_bundle

FIXTURES = Path(__file__).parent / "fixtures"


def test_canonical_findings_snapshot(tmp_path: Path) -> None:
    session = tmp_path / "session"
    shutil.copytree(FIXTURES / "demo-session", session)
    findings = findings_from_session(session)
    expected = json.loads((FIXTURES / "expected-findings.json").read_text(encoding="utf-8"))
    assert [item.id for item in findings] == expected
    path = write_findings(session, findings)
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved[0]["evidence"][0]["sha256"]
    assert "password" not in json.dumps(saved).lower()


def test_demo_engagement_plan_is_valid() -> None:
    plan = load_plan(FIXTURES / "demo-engagement.yaml")
    assert plan.engagement_id == "DEMO-2026-001"
    assert plan.allowed_targets == ("10.0.0.10",)


def test_empty_demo_engagement_writes_audited_session(tmp_path: Path) -> None:
    plan = load_plan(FIXTURES / "demo-engagement.yaml")
    result = run_engagement(plan, workspace=tmp_path)
    events = Path(str(result["session_path"])) / "events.jsonl"
    assert result["capabilities"] == []
    assert '"type": "engagement.complete"' in events.read_text(encoding="utf-8")


def test_scoped_approval_token_is_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    plan = load_plan(FIXTURES / "demo-engagement.yaml")
    key = "test-only-signing-key"
    monkeypatch.setenv("ADAF_APPROVAL_HMAC_KEY", key)
    payload = {
        "engagement_id": plan.engagement_id,
        "capabilities": ["ldap-enum"],
        "targets": [plan.dc_ip],
        "approved_by": "approver@example.test",
        "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
    }
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = (
        base64.urlsafe_b64encode(hmac.new(key.encode(), encoded.encode(), hashlib.sha256).digest())
        .decode()
        .rstrip("=")
    )
    assert (
        verify_approval(f"{encoded}.{signature}", plan, "ldap-enum")["approved_by"]
        == "approver@example.test"
    )


def test_report_bundle_html_and_pdf(tmp_path: Path) -> None:
    pytest.importorskip("reportlab")
    session = tmp_path / "session"
    shutil.copytree(FIXTURES / "demo-session", session)
    output = generate_report_bundle(session, engagement_id="DEMO-2026-001")
    assert output["finding_count"] == 2
    for report in ("executive", "technical", "remediation"):
        html = Path(str(output[f"{report}_html"]))
        pdf = Path(str(output[f"{report}_pdf"]))
        assert html.is_file() and "ADAF-ATTACK" in html.read_text(encoding="utf-8")
        assert pdf.is_file() and pdf.stat().st_size > 1000
