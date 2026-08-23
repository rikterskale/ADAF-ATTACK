"""Behavioral coverage for the single-operator execution safety boundary."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

import adaf_attack.capabilities  # noqa: F401
from adaf_attack.core.engagement import EngagementError, load_plan
from adaf_attack.core.registry import ApprovalPolicy, RiskLevel, capability_registry
from adaf_attack.core.runner import RunError, execute_capability
from adaf_attack.core.target import Target
from adaf_attack.core.vault import SessionVault, VaultError


def _target() -> Target:
    return Target(domain="corp.test", dc_ip="192.0.2.10")


@pytest.mark.parametrize(
    ("capability", "approval"),
    [
        ("coerce", ApprovalPolicy.SCOPED_TOKEN),
        ("esc-chain", ApprovalPolicy.FORCE_AND_ACK),
        ("s4u-abuse", ApprovalPolicy.FORCE_AND_ACK),
        ("dcsync", ApprovalPolicy.FORCE_AND_ACK),
    ],
)
def test_high_impact_capabilities_require_explicit_force(
    capability: str, approval: ApprovalPolicy
) -> None:
    cap = capability_registry.get(capability)
    assert cap is not None and cap.safety is not None
    assert cap.safety.approval == approval
    assert cap.safety.risk in {RiskLevel.SIDE_EFFECT, RiskLevel.DESTRUCTIVE}
    with pytest.raises(RunError, match="requires explicit authorization"):
        execute_capability(capability, _target())


def test_target_interacting_run_requires_scoped_approval_token() -> None:
    with pytest.raises(RunError, match="scoped approval token"):
        execute_capability("coerce", _target(), force=True, acknowledged=True)


def test_engagement_rejects_secondary_target_outside_allowlist(tmp_path: Path) -> None:
    plan = {
        "engagement_id": "ENG-1",
        "target": {"domain": "corp.test", "dc_ip": "192.0.2.10"},
        "allowed_capabilities": ["ldap-enum"],
        "allowed_targets": ["192.0.2.10"],
        "phases": [
            {
                "name": "recon",
                "capabilities": ["ldap-enum"],
                "options": {"host": "192.0.2.99"},
            }
        ],
    }
    path = tmp_path / "engagement.yaml"
    path.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(EngagementError, match="outside allowed_targets"):
        load_plan(path)


def test_mixed_capability_only_gates_write_parameters() -> None:
    cap = capability_registry.get("shadow-creds")
    assert cap is not None
    assert cap.requires_force is False
    with pytest.raises(RunError, match="requires explicit authorization"):
        execute_capability("shadow-creds", _target(), write_target="alice")


def test_vault_rejects_index_path_escape(tmp_path: Path) -> None:
    key = Fernet.generate_key().decode()
    vault = SessionVault(tmp_path, key=key)
    outside = tmp_path.parent / "outside-secret.txt"
    outside.write_text("must remain", encoding="utf-8")
    vault.index_path.write_text(
        json.dumps(
            {
                "version": 1,
                "items": {
                    "bad": {"kind": "secret", "secret": True, "file": "../outside-secret.txt"}
                },
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(VaultError, match="outside the vault"):
        vault.purge_all()
    assert outside.read_text(encoding="utf-8") == "must remain"
