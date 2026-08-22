"""Behavioral tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import adaf_attack.capabilities.rollback as rollback_capability
import adaf_attack.core.cleanup as cleanup
import adaf_attack.core.confidence as confidence
import adaf_attack.core.novice as novice
import adaf_attack.core.rollback as rollback
import adaf_attack.core.user_config as user_config
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import Capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def _target() -> Target:
    return Target(domain="corp.test", dc_ip="192.0.2.10")


def test_cleanup_all_ldap_paths_and_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Conn:
        result = "ok"
        calls: list[Any] = []

        def modify(self, *args: Any) -> bool:
            self.calls.append(args)
            return len(self.calls) != 4

        def unbind(self) -> None:
            return None

    conn = Conn()
    monkeypatch.setattr(cleanup, "ldap_connect", lambda target: (conn, "DC=x", None))
    artifact = tmp_path / "key.txt"
    artifact.write_text("value", encoding="utf-8")
    template = tmp_path / "template.json"
    template.write_text(json.dumps({"attrs": {"flags": 1}}), encoding="utf-8")
    session_dir = tmp_path / "cleanup"
    session_dir.mkdir()
    entries = [
        {"status": "pending", "kind": "computer-identity", "target": "a", "attribute": "x"},
        {"status": "pending", "kind": "keycred-write", "target": "b", "artifact": str(artifact)},
        {"status": "pending", "kind": "rbcd", "target": "c", "previous": ["00"]},
        {"status": "pending", "kind": "acl", "target": "d", "previous_hex": "00"},
        {"status": "pending", "kind": "gpo-link", "target": "e", "previous": "old"},
        {"status": "pending", "kind": "template-mod", "target": "f", "artifact": str(template)},
        {"status": "pending", "kind": "template-mod", "target": "g", "artifact": "missing"},
        {"status": "pending", "kind": "gpo-sysvol", "target": "..\\bad"},
        {"status": "done", "kind": "ignored"},
    ]
    (session_dir / "cleanup.json").write_text(json.dumps(entries), encoding="utf-8")
    result = cleanup.execute_cleanup(session_dir, _target())
    assert result["completed"] >= 4
    assert json.loads((session_dir / "cleanup.json").read_text())[-2]["status"] == "failed"

    session = Session(tmp_path / "registry")
    action = rollback.record_pre_state(
        session,
        kind="rbcd",
        target="x",
        attribute="a",
        previous=["00"],
        previous_hex="00",
        artifact=artifact,
        host="h",
        extra={"x": 1},
    )
    assert action["x"] == 1 and rollback.list_pending(session.root)
    assert rollback.summarize_rollbacks(session.root)["pending"] == 1
    (session.root / "cleanup.json").write_text("bad", encoding="utf-8")
    assert (
        rollback.list_pending(session.root) == []
        and rollback.summarize_rollbacks(session.root)["total"] == 0
    )
    with pytest.raises(ValueError, match="Unsupported"):
        rollback.record_pre_state(session, kind="invalid", target="x")


def test_guidance_configuration_and_rollback_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = Capability(
        id="report", summary="Reports", category="analysis", tags=(), destructive=False
    )
    assert novice.safety_summary(cap)["level"] == "GREEN"
    assert novice.plain_description(cap) and novice.explain_finding({"id": "F", "severity": "HIGH"})
    assert novice.glossary_definition("SPN") and novice.glossary_definition("missing") is None
    assert confidence.confidence_for_relation("none") == "unknown"
    assert confidence.confidence_for_relation("x", profile={"confidence": "high"}) == "high"
    assert confidence.boost_confidence("low", evidence_count=2, has_enroll=True) == "high"
    assert (
        confidence.score_chain(terminal_relation="HasSPN", path_length=2, edge_kinds=["Enroll"])[
            "confidence"
        ]
        == "high"
    )

    config = tmp_path / "config.json"
    monkeypatch.setattr(user_config, "config_path", lambda: config)
    assert user_config.load_user_config() == {}
    assert user_config.set_key("target.ldaps", "true")[1]["target.ldaps"] is True
    assert user_config.set_key("run.limit", "4")[1]["run.limit"] == 4
    assert user_config.record_recent_capability("ldap-enum") == ["ldap-enum"]
    assert user_config.recent_capabilities() == ["ldap-enum"]
    assert user_config.unset_key("run.limit")[1].get("run.limit") is None
    monkeypatch.setattr(
        user_config,
        "save_user_config",
        lambda data: (_ for _ in ()).throw(PermissionError("locked")),
    )
    assert user_config.record_recent_capability("acl-enum") == ["acl-enum", "ldap-enum"]
    with pytest.raises(ValueError, match="Unknown"):
        user_config.set_key("bad", "x")
    config.write_text("[]", encoding="utf-8")
    assert user_config.load_user_config() == {}

    session = Session(tmp_path / "rollback")
    result = rollback_capability.Rollback().run(_target(), session, AttackGraph())
    assert result["ok"] is True
    session.register_cleanup({"kind": "rbcd", "target": "x", "status": "pending"})
    result = rollback_capability.Rollback().run(_target(), session, AttackGraph())
    assert result["message"] == "force_required"
    monkeypatch.setattr(
        rollback_capability, "execute_cleanup", lambda source, target: {"completed": 1}
    )
    result = rollback_capability.Rollback().run(_target(), session, AttackGraph(), force=True)
    assert result["applied"] == 1
