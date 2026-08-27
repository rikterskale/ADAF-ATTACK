"""Behavioral coverage for Phase 2 polish follow-ons."""

from __future__ import annotations

import json
import time
from pathlib import Path

import adaf_attack.capabilities  # noqa: F401
from adaf_attack.core.registry import (
    ApprovalPolicy,
    Capability,
    RiskLevel,
    SafetyProfile,
    capability_registry,
)
from adaf_attack.core.session import Session
from adaf_attack.core.ux import advance_stage_from_log, risk_checklist, stages_for_capability


def test_advance_stage_from_log_moves_forward_only() -> None:
    stages = ["prepare", "connect", "execute", "analyze", "next-actions"]
    assert advance_stage_from_log(stages, "Workspace: /tmp/x", current=None) == "prepare"
    assert advance_stage_from_log(stages, "LDAP bind succeeded", current="prepare") == "connect"
    assert (
        advance_stage_from_log(stages, "Resolved 3 MemberOf DN edges", current="connect")
        == "analyze"
    )
    # Never move backward when an earlier keyword reappears.
    assert advance_stage_from_log(stages, "prepare workspace again", current="analyze") == "analyze"
    assert (
        advance_stage_from_log(stages, "Session directory: /tmp/done", current="analyze")
        == "next-actions"
    )


def test_advance_stage_respects_specialized_capability_stages() -> None:
    stages = stages_for_capability(capability_registry.get("esc-chain"))  # type: ignore[arg-type]
    assert "enroll" in stages
    assert "pkinit" in stages
    current = advance_stage_from_log(stages, "selecting template ESC1", current="prepare")
    assert current in {"select-template", "enroll"}
    current = advance_stage_from_log(stages, "pkinit tgt acquired", current=current)
    assert current == "pkinit"


def test_risk_checklist_requires_scoped_token_when_policy_says_so() -> None:
    cap = Capability(
        id="token-demo",
        summary="Scoped token demo",
        destructive=True,
        safety=SafetyProfile(
            risk=RiskLevel.DESTRUCTIVE,
            approval=ApprovalPolicy.SCOPED_TOKEN,
            network_side_effect=True,
            modifies_directory=True,
        ),
    )
    checklist = risk_checklist(cap)
    token_item = next(item for item in checklist["items"] if item["id"] == "approval_token")
    assert token_item["required"] is True
    assert "approval-token" in token_item["label"]


def test_session_log_stamps_incremental_duration_ms(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    session.log("run.start", capability="ldap-enum")
    time.sleep(0.02)
    session.log("progress.note", message="still working")
    session.log("run.complete", capability="ldap-enum", duration_ms=999)
    events = [
        json.loads(line)
        for line in (session.root / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert events[0]["duration_ms"] >= 0
    assert events[1]["duration_ms"] >= events[0]["duration_ms"]
    # Explicit caller-provided duration wins.
    assert events[2]["duration_ms"] == 999
    assert all(event.get("correlation_id") for event in events)
