"""Experimental tracking stubs: registered, inert, and classified."""

from __future__ import annotations

import inspect
from pathlib import Path

import adaf_attack.capabilities  # noqa: F401
from adaf_attack.capabilities import planned_offensive
from adaf_attack.capabilities.planned_offensive import (
    NEXT_PR_IDS,
    PLANNED_CAPABILITIES,
    WAVE2_IDS,
    next_pr_ids,
    planned_destructive_ids,
    planned_ids,
    wave2_ids,
)
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import capability_registry
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def test_planned_ids_are_unique() -> None:
    ids = planned_ids()
    assert len(ids) == len(set(ids))
    assert len(ids) == 40


def test_planned_module_does_not_claim_rollback_primitives() -> None:
    source = inspect.getsource(planned_offensive)
    assert "register_cleanup" not in source
    assert "record_pre_state" not in source


def test_tracking_run_writes_evidence_without_claiming_success(tmp_path: Path) -> None:
    cap = capability_registry.get("badsuccessor")
    assert cap is not None and cap.runner is not None
    session = Session(base_dir=tmp_path)
    target = Target(domain="corp.test", dc_ip="10.0.0.1")
    result = cap.runner.run(target, session, AttackGraph(), force=True)
    assert result["ok"] is False
    assert result["implemented"] is False
    assert result["status"] == "experimental"
    assert result["capability"] == "badsuccessor"
    written = session.path("badsuccessor.json")
    assert written.is_file()
    assert "tracking only" in written.read_text(encoding="utf-8")


def test_destructive_flags_match_tuple() -> None:
    destructive = set(planned_destructive_ids())
    for cap_id, _summary, is_destructive, *_rest in PLANNED_CAPABILITIES:
        cap = capability_registry.get(cap_id)
        assert cap is not None
        assert cap.destructive is is_destructive
        if is_destructive:
            assert cap_id in destructive


def test_next_pr_ids_are_registered_and_tagged() -> None:
    assert len(NEXT_PR_IDS) == 11
    assert not (NEXT_PR_IDS & WAVE2_IDS)
    for cap_id in next_pr_ids():
        cap = capability_registry.get(cap_id)
        assert cap is not None, cap_id
        assert "next-pr" in cap.tags
        assert "experimental" in cap.tags


def test_wave2_ids_are_registered_and_tagged() -> None:
    assert len(WAVE2_IDS) == 12
    for cap_id in wave2_ids():
        cap = capability_registry.get(cap_id)
        assert cap is not None, cap_id
        assert "wave-2" in cap.tags
