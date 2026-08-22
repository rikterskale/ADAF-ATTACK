"""Behavioral tests."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import adaf_attack.capabilities.coerce as coerce
import adaf_attack.capabilities.credential_inventory as credential_inventory
import adaf_attack.capabilities.esc_chain as esc_chain
import adaf_attack.capabilities.identity_bridge as identity_bridge
import adaf_attack.capabilities.rbcd as rbcd
import adaf_attack.capabilities.rodc_delegation as rodc
import adaf_attack.capabilities.s4u_abuse as s4u
from adaf_attack.capabilities.adcs_policy_probe import AdcsPolicyProbe
from adaf_attack.capabilities.gpo_abuse import _impact_score
from adaf_attack.capabilities.next_actions import NextActions
from adaf_attack.capabilities.rollback import Rollback
from adaf_attack.core.adcs_analyze import classify_modern_esc
from adaf_attack.core.confidence import boost_confidence
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def test_modern_adcs_policy_and_gpo_impact_tiers() -> None:
    result = classify_modern_esc(
        template_flags={
            "esc2_candidate": True,
            "esc3_agent_template": True,
            "esc9_candidate": True,
        },
        enroll_principal_count=1,
        dangerous_acl=True,
        policy={
            "weak_certificate_mapping": True,
            "rpc_encryption_not_enforced": True,
            "issuance_policy_group_links": ["admins"],
            "application_policy_maps_to_group": True,
            "shell_access_via_certificate": True,
            "privileged_enrollment_agent": True,
        },
    )
    assert {"ESC2", "ESC3", "ESC4", "ESC9", "ESC10", "ESC11", "ESC13", "ESC14", "ESC15"} <= set(
        result["candidates"]
    )
    assert (
        _impact_score(writers=5, link_count=20, linked_to_domain=True, linked_to_root_ou=True)[
            "tier"
        ]
        == "critical"
    )
    assert (
        _impact_score(writers=0, link_count=0, linked_to_domain=False, linked_to_root_ou=False)[
            "tier"
        ]
        == "low"
    )
    assert boost_confidence("invalid") == "unknown"


def test_policy_probe_records_optional_esc14_and_esc15(tmp_path: Path) -> None:
    artifact = tmp_path / "policy.json"
    artifact.write_text(
        json.dumps({"shell_access_via_certificate": True, "privileged_enrollment_agent": True}),
        encoding="utf-8",
    )
    result = AdcsPolicyProbe().run(
        Target(domain="corp.test", dc_ip="192.0.2.10"),
        Session(tmp_path / "session"),
        AttackGraph(),
        artifact=artifact,
    )
    assert result["esc14_candidates"] == ["shell-path"]
    assert result["esc15_candidates"] == ["enrollment-agent"]


def test_small_helper_guards_and_classification_edges(tmp_path: Path) -> None:
    """Exercise defensive normalization paths without contacting a directory."""
    assert coerce._load_allowlist({"host": "APP01"}, None) == ["APP01"]
    assert esc_chain._signals_from_template({"esc1_candidate": True}) == ["ESC1"]
    assert esc_chain._pick_template({"templates": [{"esc_tags": ["ESC9"], "cn": "T"}]}) == {
        "esc_tags": ["ESC9"],
        "cn": "T",
    }

    class Empty:
        value = None

        def __bool__(self) -> bool:
            return True

    entry = SimpleNamespace(example=Empty())
    assert identity_bridge._list_attr(entry, "example") == []
    assert rodc._list_attr(entry, "example") == []
    assert rbcd._list_attr(entry, "example") == []
    assert rodc._uac(SimpleNamespace(userAccountControl=SimpleNamespace(value="bad"))) == 0
    assert rbcd._list_attr(SimpleNamespace(example=["one", "two"]), "example") == ["one", "two"]

    outside = tmp_path / "not-a-file"
    outside.mkdir()
    session = Session(tmp_path / "session")
    session.root.mkdir(parents=True, exist_ok=True)
    (session.root / "sample.ccache").write_text("ticket", encoding="utf-8")
    assert credential_inventory._scan_artifacts(session)[0]["kind"] == "ccache"
    with pytest.raises(RuntimeError, match="purge requires"):
        credential_inventory.CredentialInventory().run(
            Target(domain="corp.test", dc_ip="192.0.2.10"),
            session,
            AttackGraph(),
            operation="purge",
            force=True,
        )
    with pytest.raises(RuntimeError, match="mark-for-rotation"):
        credential_inventory.CredentialInventory().run(
            Target(domain="corp.test", dc_ip="192.0.2.10"),
            session,
            AttackGraph(),
            operation="rotate",
        )


def test_coercion_allowlist_guards_and_selected_host(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(coerce, "require_impacket", lambda _name: None)
    target = Target(domain="corp.test", dc_ip="")
    with pytest.raises(RuntimeError, match="approved allowlist"):
        coerce.Coerce().run(target, Session(tmp_path / "empty"), AttackGraph(), listener="listener")
    monkeypatch.setattr(
        coerce,
        "_trigger",
        lambda _target, host, _listener, method: {"ok": True, "host": host, "method": method},
    )
    result = coerce.Coerce().run(
        target,
        Session(tmp_path / "selected"),
        AttackGraph(),
        listener="listener",
        allow_hosts="APP01,APP02",
        host="APP02",
        methods="petitpotam",
    )
    assert result["targets"] == ["APP02"]


def test_remaining_pure_error_and_tier_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from adaf_attack.core import confidence, user_config
    from adaf_attack.core.adcs_analyze import analyze_template_flags

    assert (
        _impact_score(writers=0, link_count=9, linked_to_domain=False, linked_to_root_ou=False)[
            "tier"
        ]
        == "high"
    )
    assert (
        _impact_score(writers=2, link_count=0, linked_to_domain=False, linked_to_root_ou=False)[
            "tier"
        ]
        == "medium"
    )
    assert (
        "ESC9"
        in analyze_template_flags(enrollment_flags=0x80000, ekus=["1.3.6.1.5.5.7.3.2"])["esc_tags"]
    )
    monkeypatch.setattr(confidence, "CONFIDENCE_RANK", {})
    assert confidence.boost_confidence("custom") == "custom"
    monkeypatch.setattr(user_config, "load_user_config", lambda: {"ui.recent_capabilities": "bad"})
    assert user_config.recent_capabilities() == []
    with pytest.raises(RuntimeError, match="Session directory"):
        Rollback().run(
            Target(domain="corp.test", dc_ip="192.0.2.10"),
            Session(tmp_path / "out"),
            AttackGraph(),
            from_session=tmp_path / "missing",
        )

    class ChainsOnly:
        nodes = {"a": object()}
        edges: list[object] = []

        def rank_exploit_chains(self, **_kwargs):
            return [{"terminal_relation": "WriteRBCD", "length": 1, "edges": []}]

    assert (
        NextActions().run(
            Target(domain="corp.test", dc_ip="192.0.2.10"), Session(tmp_path / "next"), ChainsOnly()
        )["actions"]
        == []
    )


def test_s4u_precondition_evidence_includes_matching_and_global_edges() -> None:
    graph = AttackGraph()
    graph.add_edge("ACCOUNT@OTHER", "COMPUTER@APP", "AllowedToDelegate")
    graph.add_edge("ACCOUNT@CONTROLLER", "COMPUTER@APP", "WriteRBCD")
    result = s4u._precondition_evidence(graph, "controller")
    assert result["evidence_count"] == 2
    assert result["has_constrained_signal"] is True
    assert result["has_rbcd_signal"] is True


def test_vault_removes_encrypted_blob(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from cryptography.fernet import Fernet

    monkeypatch.setenv("ADAF_SESSION_VAULT_KEY", Fernet.generate_key().decode())
    session = Session(tmp_path / "vault")
    vault = session.vault()
    vault.put("secret", "password", "value", secret=True)
    assert vault.delete("secret") is True
    assert vault.delete("missing") is False
