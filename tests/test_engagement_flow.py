"""Offline coverage for engagement plan loading, approval tokens, and execution."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from adaf_attack.core.engagement import (
    EngagementError,
    EngagementPlan,
    load_plan,
    run_engagement,
    verify_approval,
)
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import Capability, capability_registry
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


@pytest.fixture()
def fake_caps() -> Iterator[None]:
    added = []

    class _Runner:
        def __init__(self, destructive: bool) -> None:
            self.destructive = destructive
            self.runs: list[bool] = []

        def run(
            self,
            target: Target,
            session: Session,
            graph: AttackGraph,
            *,
            include_secrets: bool = False,
            force: bool = False,
            **kwargs: Any,
        ) -> dict[str, Any]:
            self.runs.append(force)
            return {"ok": True}

    for cap_id, destructive in (("eng-enum", False), ("eng-write", True)):
        capability_registry._capabilities[cap_id] = Capability(
            id=cap_id, summary="t", destructive=destructive, runner=_Runner(destructive)
        )
        added.append(cap_id)
    yield None
    for cap_id in added:
        capability_registry._capabilities.pop(cap_id, None)


def _write_plan(path: Path, **overrides: Any) -> Path:
    plan = {
        "engagement_id": "ENG-1",
        "target": {"domain": "corp.test", "dc_ip": "192.0.2.10"},
        "allowed_capabilities": ["eng-enum"],
        "phases": [{"name": "recon", "capabilities": ["eng-enum"]}],
    }
    plan.update(overrides)
    path.write_text(json.dumps(plan), encoding="utf-8")
    return path


def test_load_plan_bad_yaml(tmp_path: Path) -> None:
    p = tmp_path / "plan.yaml"
    p.write_text("::: not: valid: yaml: [", encoding="utf-8")
    with pytest.raises(EngagementError, match="Cannot load engagement YAML"):
        load_plan(p)


def test_load_plan_missing_keys(tmp_path: Path) -> None:
    p = tmp_path / "plan.yaml"
    p.write_text(json.dumps({"engagement_id": "x"}), encoding="utf-8")
    with pytest.raises(EngagementError, match="Missing required keys"):
        load_plan(p)


def test_load_plan_missing_target_fields(tmp_path: Path, fake_caps: None) -> None:
    p = _write_plan(tmp_path / "plan.yaml", target={"domain": "corp.test"})
    with pytest.raises(EngagementError, match="target.domain and target.dc_ip"):
        load_plan(p)


def test_load_plan_unknown_capability(tmp_path: Path) -> None:
    p = _write_plan(tmp_path / "plan.yaml", allowed_capabilities=["nope-not-real"])
    with pytest.raises(EngagementError, match="Unknown allowed capabilities"):
        load_plan(p)


def test_load_plan_valid(tmp_path: Path, fake_caps: None) -> None:
    plan = load_plan(_write_plan(tmp_path / "plan.yaml"))
    assert plan.engagement_id == "ENG-1"
    assert plan.allowed_capabilities == ("eng-enum",)
    assert plan.allowed_targets == ("192.0.2.10",)


def _make_token(key: str, payload: dict[str, Any]) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = (
        base64.urlsafe_b64encode(hmac.new(key.encode(), encoded.encode(), hashlib.sha256).digest())
        .decode()
        .rstrip("=")
    )
    return f"{encoded}.{sig}"


def _plan() -> EngagementPlan:
    return EngagementPlan(
        engagement_id="ENG-1",
        domain="corp.test",
        dc_ip="192.0.2.10",
        allowed_capabilities=("eng-write",),
        phases=(),
        allowed_targets=("192.0.2.10",),
    )


def test_verify_approval_requires_key(monkeypatch: Any) -> None:
    monkeypatch.delenv("ADAF_APPROVAL_HMAC_KEY", raising=False)
    with pytest.raises(EngagementError, match="ADAF_APPROVAL_HMAC_KEY is required"):
        verify_approval("a.b", _plan(), "eng-write")


def test_verify_approval_bad_format(monkeypatch: Any) -> None:
    monkeypatch.setenv("ADAF_APPROVAL_HMAC_KEY", "secret")
    with pytest.raises(EngagementError, match="Invalid approval token format"):
        verify_approval("not-a-valid-token", _plan(), "eng-write")


def test_verify_approval_bad_signature(monkeypatch: Any) -> None:
    monkeypatch.setenv("ADAF_APPROVAL_HMAC_KEY", "secret")
    token = _make_token("wrong-key", {"engagement_id": "ENG-1", "capabilities": ["eng-write"]})
    with pytest.raises(EngagementError, match="signature is invalid"):
        verify_approval(token, _plan(), "eng-write")


def test_verify_approval_scope_mismatch(monkeypatch: Any) -> None:
    monkeypatch.setenv("ADAF_APPROVAL_HMAC_KEY", "secret")
    token = _make_token("secret", {"engagement_id": "OTHER", "capabilities": ["eng-write"]})
    with pytest.raises(EngagementError, match="scope does not match"):
        verify_approval(token, _plan(), "eng-write")


def test_verify_approval_wrong_target(monkeypatch: Any) -> None:
    monkeypatch.setenv("ADAF_APPROVAL_HMAC_KEY", "secret")
    token = _make_token(
        "secret",
        {"engagement_id": "ENG-1", "capabilities": ["eng-write"], "targets": ["10.9.9.9"]},
    )
    with pytest.raises(EngagementError, match="does not permit this target"):
        verify_approval(token, _plan(), "eng-write")


def test_verify_approval_expired(monkeypatch: Any) -> None:
    monkeypatch.setenv("ADAF_APPROVAL_HMAC_KEY", "secret")
    token = _make_token(
        "secret",
        {
            "engagement_id": "ENG-1",
            "capabilities": ["eng-write"],
            "targets": ["192.0.2.10"],
            "exp": 1,
        },
    )
    with pytest.raises(EngagementError, match="has expired"):
        verify_approval(token, _plan(), "eng-write")


def test_verify_approval_valid(monkeypatch: Any) -> None:
    monkeypatch.setenv("ADAF_APPROVAL_HMAC_KEY", "secret")
    exp = int(datetime.now(UTC).timestamp()) + 3600
    token = _make_token(
        "secret",
        {
            "engagement_id": "ENG-1",
            "capabilities": ["eng-write"],
            "targets": ["192.0.2.10"],
            "exp": exp,
            "approval_id": "AP-1",
        },
    )
    payload = verify_approval(token, _plan(), "eng-write")
    assert payload["approval_id"] == "AP-1"


def test_run_engagement_dc_not_allowed(fake_caps: None, tmp_path: Path) -> None:
    plan = EngagementPlan(
        engagement_id="ENG-1",
        domain="corp.test",
        dc_ip="192.0.2.10",
        allowed_capabilities=("eng-enum",),
        phases=(),
        allowed_targets=("10.0.0.1",),
    )
    with pytest.raises(EngagementError, match="not in allowed_targets"):
        run_engagement(plan, workspace=tmp_path)


def test_run_engagement_happy_path(fake_caps: None, tmp_path: Path) -> None:
    plan = EngagementPlan(
        engagement_id="ENG-1",
        domain="corp.test",
        dc_ip="192.0.2.10",
        allowed_capabilities=("eng-enum",),
        phases=({"name": "recon", "capabilities": ["eng-enum"]},),
        allowed_targets=("192.0.2.10",),
    )
    out = run_engagement(plan, workspace=tmp_path)
    assert out["engagement_id"] == "ENG-1"
    assert out["capabilities"] == ["eng-enum"]
    assert "findings_path" in out


def test_run_engagement_destructive_requires_token(fake_caps: None, tmp_path: Path) -> None:
    plan = EngagementPlan(
        engagement_id="ENG-1",
        domain="corp.test",
        dc_ip="192.0.2.10",
        allowed_capabilities=("eng-write",),
        phases=({"name": "act", "capabilities": ["eng-write"]},),
        allowed_targets=("192.0.2.10",),
    )
    with pytest.raises(EngagementError, match="Approval token required"):
        run_engagement(plan, workspace=tmp_path)


def test_run_engagement_capability_not_in_scope(fake_caps: None, tmp_path: Path) -> None:
    plan = EngagementPlan(
        engagement_id="ENG-1",
        domain="corp.test",
        dc_ip="192.0.2.10",
        allowed_capabilities=("eng-enum",),
        phases=({"name": "recon", "capabilities": ["eng-write"]},),
        allowed_targets=("192.0.2.10",),
    )
    with pytest.raises(EngagementError, match="not allowed by engagement scope"):
        run_engagement(plan, workspace=tmp_path)
