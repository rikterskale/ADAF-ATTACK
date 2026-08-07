"""Offline tests for export, hybrid, ticket, and workflow capabilities."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.fernet import Fernet

import adaf_attack.capabilities.acl_write as acl_write
import adaf_attack.capabilities.bloodhound_export as bloodhound_export
import adaf_attack.capabilities.identity_bridge as identity_bridge
import adaf_attack.capabilities.pkinit_auth as pkinit_auth
import adaf_attack.capabilities.ticket_lifecycle as ticket_lifecycle
import adaf_attack.capabilities.workflow_wrappers as workflow_wrappers
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Conn:
    def __init__(self, entries: list[Any] | None = None) -> None:
        self.entries = entries or []
        self.unbound = False
        self.modified: Any = None

    def search(self, *args: Any, **kwargs: Any) -> None:
        pass

    def modify(self, *args: Any, **kwargs: Any) -> bool:
        self.modified = (args, kwargs)
        return True

    def unbind(self) -> None:
        self.unbound = True


def _target() -> Target:
    return Target(domain="corp.test", dc_ip="192.0.2.10")


def test_hybrid_signals_detects_multiple_markers(monkeypatch: Any, tmp_path: Path) -> None:
    entry = SimpleNamespace(
        sAMAccountName="ADCONNECT$",
        description="Azure AD Connect service",
        servicePrincipalName=["HTTP/seamless sso"],
    )
    conn = _Conn([entry])
    monkeypatch.setattr(
        identity_bridge, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None)
    )
    graph = AttackGraph()
    result = identity_bridge.HybridSignals().run(_target(), Session(tmp_path), graph)

    assert result["count"] == 2 and conn.unbound
    assert {edge.kind for edge in graph.edges} == {"PossibleEntraPivot"}


def test_bloodhound_import_requires_artifact(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="requires --artifact"):
        identity_bridge.BloodhoundImport().run(_target(), Session(tmp_path), AttackGraph())


def test_bloodhound_export_hydrates_saved_graph(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(tmp_path)
    session.path("graph.json").write_text(
        json.dumps({"nodes": [{"id": "USER@ALICE", "kind": "User", "properties": {}}], "edges": []})
    )
    captured: list[Path] = []
    monkeypatch.setattr(
        bloodhound_export, "save_bloodhound", lambda graph, path, domain: captured.append(path)
    )
    monkeypatch.setattr(
        bloodhound_export, "save_bloodhound_zip", lambda graph, path, domain: captured.append(path)
    )

    result = bloodhound_export.BloodhoundExport().run(_target(), session, AttackGraph())

    assert result["summary"]["nodes"] == 1
    assert [path.name for path in captured] == ["bloodhound.json", "bloodhound.zip"]


def test_acl_write_validates_and_records_rollback(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(tmp_path)
    with pytest.raises(RuntimeError, match="requires --force"):
        acl_write.AclWrite().run(_target(), session, AttackGraph())
    conn = _Conn()
    monkeypatch.setattr(acl_write, "ldap_connect", lambda target: (conn, "", None))
    monkeypatch.setattr(acl_write, "fetch_sd", lambda conn, dn: b"old")

    result = acl_write.AclWrite().run(
        _target(),
        session,
        AttackGraph(),
        force=True,
        write_target="CN=Alice",
        descriptor_hex="0011",
    )

    assert result == {"target": "CN=Alice", "ok": True}
    assert conn.unbound and json.loads(session.path("cleanup.json").read_text())[0]["kind"] == "acl"


def test_ticket_lifecycle_inventory_import_and_export(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setenv("ADAF_SESSION_VAULT_KEY", Fernet.generate_key().decode())
    session = Session(tmp_path)
    source = tmp_path / "ticket.ccache"
    source.write_bytes(b"ticket")
    capability = ticket_lifecycle.TicketLifecycle()
    imported = capability.run(
        _target(), session, AttackGraph(), operation="import-ccache", artifact=source
    )
    exported = capability.run(_target(), session, AttackGraph(), operation="export-ccache")
    inventory = capability.run(_target(), session, AttackGraph())

    assert Path(imported["ccache"]).is_file() and Path(exported["ccache"]).is_file()
    assert "imported-ticket.ccache" in inventory["artifacts"]

    pfx_source = tmp_path / "certificate.pfx"
    pfx_source.write_bytes(b"pfx")
    pfx_import = capability.run(
        _target(), session, AttackGraph(), operation="import-pfx", artifact=pfx_source
    )
    pfx_export = capability.run(_target(), session, AttackGraph(), operation="export-pfx")
    assert Path(pfx_import["pfx"]).is_file() and Path(pfx_export["pfx"]).read_bytes() == b"pfx"


@pytest.mark.parametrize(
    ("operation", "message"),
    [
        ("import-ccache", "existing ccache"),
        ("import-pfx", "existing PFX"),
        ("unsupported", "Unsupported operation"),
    ],
)
def test_ticket_lifecycle_rejects_invalid_artifacts(
    monkeypatch: Any, tmp_path: Path, operation: str, message: str
) -> None:
    monkeypatch.setenv("ADAF_SESSION_VAULT_KEY", Fernet.generate_key().decode())
    with pytest.raises(RuntimeError, match=message):
        ticket_lifecycle.TicketLifecycle().run(
            _target(),
            Session(tmp_path),
            AttackGraph(),
            operation=operation,
            artifact=tmp_path / "missing",
        )


def test_workflow_wrappers_guard_and_record_success_paths(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(tmp_path)
    with pytest.raises(RuntimeError, match="shadow-pkinit-workflow requires"):
        workflow_wrappers.ShadowPkinitWorkflow().run(_target(), session, AttackGraph())
    monkeypatch.setattr(
        workflow_wrappers.ShadowCreds,
        "run",
        lambda self, *args, **kwargs: {
            "write_attempt": {"ok": True, "key_pem": "k", "cert_pem": "c"}
        },
    )
    monkeypatch.setattr(
        workflow_wrappers.PkinitAuth, "run", lambda self, *args, **kwargs: {"ok": True}
    )
    result = workflow_wrappers.ShadowPkinitWorkflow().run(
        _target(), session, AttackGraph(), force=True, write_target="alice"
    )

    assert result["ok"] is True
    assert session.path("shadow-pkinit-workflow.json").is_file()


def test_pkinit_auth_validates_force_and_missing_material(tmp_path: Path) -> None:
    capability = pkinit_auth.PkinitAuth()
    with pytest.raises(RuntimeError, match="requires --force"):
        capability.run(_target(), Session(tmp_path), AttackGraph())
    with pytest.raises(RuntimeError, match="No shadow key/cert"):
        capability.run(_target(), Session(tmp_path), AttackGraph(), force=True, sam="alice")


def test_pkinit_auth_records_certipy_failure_playbook(monkeypatch: Any, tmp_path: Path) -> None:
    pfx = tmp_path / "shadow.pfx"
    pfx.write_bytes(b"not-parsed-by-mocked-certipy")
    monkeypatch.setattr(
        pkinit_auth.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1, stdout="", stderr="certipy unavailable"
        ),
    )
    session = Session(tmp_path)
    result = pkinit_auth.PkinitAuth().run(
        Target(domain="corp.test", dc_ip="192.0.2.10", username="alice"),
        session,
        AttackGraph(),
        force=True,
        pfx=str(pfx),
    )

    assert result["method"] == "certipy"
    assert result["ok"] is False
    assert Path(result["playbook"]).is_file()
