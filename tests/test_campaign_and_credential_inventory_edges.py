"""Behavioral tests."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.fernet import Fernet

import adaf_attack.capabilities.campaign_run as campaign_run
import adaf_attack.capabilities.credential_inventory as credential_inventory
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def _target() -> Target:
    return Target(domain="corp.test", dc_ip="192.0.2.10")


def _session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Session:
    monkeypatch.setenv("ADAF_SESSION_VAULT_KEY", Fernet.generate_key().decode())
    return Session(tmp_path)


def _approval_token(session: Session, target: Target, capability: str) -> str:
    key = "campaign-test-key"
    payload = {
        "engagement_id": session.session_id,
        "capabilities": [capability],
        "targets": [target.dc_ip],
        "approved_by": "test",
        "exp": int(time.time()) + 3600,
    }
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = (
        base64.urlsafe_b64encode(hmac.new(key.encode(), encoded.encode(), hashlib.sha256).digest())
        .decode()
        .rstrip("=")
    )
    return f"{encoded}.{signature}"


def test_campaign_helpers_and_all_phase_outcomes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _session(tmp_path / "session", monkeypatch)
    session.vault().put("token", "password", "value", secret=True, metadata={"owner": "ops"})
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"phases": [{"id": "ok", "capability": "ok"}]}), encoding="utf-8")
    assert campaign_run._load_phases({"plan": plan}) == [{"id": "ok", "capability": "ok"}]
    assert campaign_run._load_phases({}) == campaign_run.DEFAULT_PHASES
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"phases": "bad"}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="phases list"):
        campaign_run._load_phases({"plan": bad})
    with pytest.raises(RuntimeError, match="not found"):
        campaign_run._load_phases({"plan": tmp_path / "missing"})
    handoff = campaign_run._vault_hand_off(session, {"vault_refs": ["token", "missing"]})
    assert handoff["used"] == ["token"] and "error" in handoff["values"]["missing"]
    assert campaign_run._vault_hand_off(session, {}) == {"used": [], "values": {}}

    class Good:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, str]:
            return {"done": "yes"}

    class Bad:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, str]:
            raise RuntimeError("expected failure")

    registry = {
        "good": SimpleNamespace(runner=Good()),
        "bad": SimpleNamespace(runner=Bad()),
    }
    monkeypatch.setattr(campaign_run.capability_registry, "get", registry.get)
    phases = [
        {"id": "needs-force", "capability": "good", "destructive": True},
        {"id": "needs-token", "capability": "good", "destructive": True},
        {"id": "unknown", "capability": "unknown"},
        {"id": "needs-vault", "capability": "good", "require_vault": True},
        {"id": "good", "capability": "good", "vault_refs": ["token"]},
        {"id": "bad", "capability": "bad"},
    ]
    execution_plan = tmp_path / "execution-plan.json"
    execution_plan.write_text(json.dumps({"phases": phases}), encoding="utf-8")
    result = campaign_run.CampaignRun().run(_target(), session, AttackGraph(), plan=execution_plan)
    assert result["skipped"] == 3 and result["failed"] == 2 and result["completed"] == 1
    monkeypatch.setenv("ADAF_APPROVAL_HMAC_KEY", "campaign-test-key")
    result = campaign_run.CampaignRun().run(
        _target(),
        session,
        AttackGraph(),
        plan=execution_plan,
        force=True,
        approval_token=_approval_token(session, _target(), "good"),
        engagement_id=session.session_id,
    )
    assert result["completed"] == 3
    assert Path(result["purple_handoff"]).is_file()
    assert campaign_run._purple_package(
        session, [{"ok": True, "capability": "rbcd"}], AttackGraph()
    )["recommended_detections"]


def test_credential_inventory_export_rotation_and_purge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _session(tmp_path / "session", monkeypatch)
    vault = session.vault()
    vault.put("plain", "password", "visible", secret=False, metadata={"team": "red"})
    vault.put("secret", "ntlm-hash", {"nt": "a" * 32}, secret=True, metadata={"team": "red"})
    for name in ("ticket.ccache", "cert.pfx", "key.pem", "shadow-x.dnbinary.txt", "imported-x"):
        session.path(name).write_text("artifact", encoding="utf-8")
    scanned = credential_inventory._scan_artifacts(session)
    assert {item["kind"] for item in scanned} >= {"ccache", "pfx", "pem", "keycred", "artifact"}
    catalog = credential_inventory._vault_catalog(session, include_secrets=True)
    assert {item["name"] for item in catalog} == {"plain", "secret"}
    inventory = credential_inventory._inventory(session, include_secrets=True)
    assert inventory["vault_count"] == 2 and inventory["artifact_count"] >= 5
    exported = credential_inventory._export_items(
        session, names=["plain", "secret", "ticket.ccache", "missing"], include_secrets=False
    )
    assert len(exported["exported"]) == 3 and exported["errors"]
    exported_secret = credential_inventory._export_items(
        session, names=["secret"], include_secrets=True
    )
    assert Path(exported_secret["exported"][0]["path"]).is_file()
    rotation = credential_inventory._mark_rotation(session, ["plain", "missing"])
    assert [item["ok"] for item in rotation["markers"]] == [True, True]
    removed = credential_inventory._purge(
        session, names=["plain", "ticket.ccache"], purge_all=False, purge_files=True
    )
    assert removed["removed_vault"] == ["plain"] and removed["removed_files"] == ["ticket.ccache"]
    removed_all = credential_inventory._purge(session, names=None, purge_all=True, purge_files=True)
    assert removed_all["removed_vault"]

    session = _session(tmp_path / "run-session", monkeypatch)
    session.vault().put("item", "password", "v", secret=False)
    inventory_result = credential_inventory.CredentialInventory().run(
        _target(), session, AttackGraph()
    )
    assert inventory_result["vault_count"] == 1
    exported_result = credential_inventory.CredentialInventory().run(
        _target(), session, AttackGraph(), operation="export", names="item"
    )
    assert exported_result["exported"]
    rotated_result = credential_inventory.CredentialInventory().run(
        _target(), session, AttackGraph(), operation="mark-for-rotation", names=["item"]
    )
    assert rotated_result["markers"][0]["ok"]
    with pytest.raises(RuntimeError, match="requires --force"):
        credential_inventory.CredentialInventory().run(
            _target(), session, AttackGraph(), operation="purge", names="item"
        )
    purged_result = credential_inventory.CredentialInventory().run(
        _target(), session, AttackGraph(), operation="purge", names="item", force=True
    )
    assert purged_result["removed_vault"] == ["item"]
    with pytest.raises(RuntimeError, match="Unsupported operation"):
        credential_inventory.CredentialInventory().run(
            _target(), session, AttackGraph(), operation="unknown"
        )


def test_campaign_purple_and_vault_error_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _session(tmp_path / "session", monkeypatch)

    class BrokenGraph:
        def rank_exploit_chains(self, limit: int) -> list[dict[str, Any]]:
            raise RuntimeError("broken")

    assert campaign_run._purple_package(session, [], BrokenGraph())["top_exploit_chains"] == []
    session.vault().put("secret", "password", "value", secret=True)
    monkeypatch.delenv("ADAF_SESSION_VAULT_KEY")
    assert "value_error" in credential_inventory._vault_catalog(session, include_secrets=True)[0]


def test_campaign_approval_and_credential_value_shapes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _session(tmp_path / "session", monkeypatch)
    session.vault().put("text", "password", "secret", secret=True)
    session.vault().put("mapping", "token", {"a": 1}, secret=True)
    catalog = credential_inventory._vault_catalog(session, include_secrets=True)
    assert {item["name"] for item in catalog if item.get("value_len") == 6} == {"text"}
    assert next(item for item in catalog if item["name"] == "mapping")["value_keys"] == ["a"]
    plan = tmp_path / "approval.json"
    plan.write_text(
        json.dumps([{"id": "danger", "capability": "anything", "destructive": True}]),
        encoding="utf-8",
    )
    result = campaign_run.CampaignRun().run(
        _target(), session, AttackGraph(), force=True, plan=plan, approval_token="wrong"
    )
    assert result["phases"][0]["skipped"] == "approval_token_required"
