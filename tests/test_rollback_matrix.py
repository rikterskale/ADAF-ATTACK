"""Per-capability rollback-behavior matrix (Release Readiness §4).

Enforces that recovery actually works, not merely that a rollback is recorded:

* Every rollback *kind* a destructive capability records is either
  auto-revertable (``execute_cleanup`` restores prior state) or explicitly
  advisory (manual review; not auto-reverted).
* Each auto-revertable kind, fed back through ``execute_cleanup`` with a mocked
  directory connection, round-trips to ``completed`` and issues the expected
  reversal operation.
* Advisory kinds are proven *not* auto-reverted (so they can't masquerade as
  recoverable).

This is the gate that caught ``shadow-creds`` recording a rollback the engine
could not execute. A new destructive capability that records an unclassified or
unrevertable kind fails here.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any

import pytest

import adaf_attack.capabilities  # noqa: F401  # register every capability
import adaf_attack.capabilities.gpo_sysvol as gpo_sysvol
import adaf_attack.core.cleanup as cleanup
from adaf_attack.core.registry import capability_registry
from adaf_attack.core.target import Target

_ROLLBACK_PRIMITIVES = ("register_cleanup", "record_pre_state")

# Destructive capability -> (rollback kind it records, classification).
#   revertable: execute_cleanup restores prior target state.
#   advisory:   no automatic revert is possible (remote code ran, creds were
#               relayed); the operator reviews and reverts manually.
_CAPABILITY_ROLLBACK: dict[str, tuple[str, str]] = {
    "acl-write": ("acl", "revertable"),
    "gpo-link": ("gpo-link", "revertable"),
    "gpo-sysvol": ("gpo-sysvol", "revertable"),
    "rbcd": ("rbcd", "revertable"),
    "template-mod": ("template-mod", "revertable"),
    "shadow-creds": ("shadow-creds", "revertable"),
    "impacket-exec": ("remote-exec", "advisory"),
    "ntlm-relay": ("ntlm-relay", "advisory"),
}


class _Conn:
    def __init__(self) -> None:
        self.result = "success"
        self.modifies: list[tuple[str, Any]] = []

    def modify(self, dn: str, changes: Any) -> bool:
        self.modifies.append((dn, changes))
        return True

    def unbind(self) -> None:
        return None


def _target() -> Target:
    return Target(domain="corp.test", dc_ip="192.0.2.10")


def _write_cleanup(session: Path, entry: dict[str, Any]) -> None:
    (session / "cleanup.json").write_text(json.dumps([entry]), encoding="utf-8")


def _ldap_revertable_entries(tmp_path: Path) -> dict[str, dict[str, Any]]:
    keycred = tmp_path / "shadow.dnbinary.txt"
    keycred.write_text("B:828:00AA:CN=Owner", encoding="utf-8")
    template = tmp_path / "template.json"
    template.write_text(json.dumps({"attrs": {"flags": 1}}), encoding="utf-8")
    return {
        "acl": {
            "kind": "acl",
            "status": "pending",
            "target": "CN=D,DC=corp,DC=test",
            "previous_hex": "0102",
        },
        "gpo-link": {
            "kind": "gpo-link",
            "status": "pending",
            "target": "OU=E,DC=corp,DC=test",
            "previous": "[LDAP://cn={GUID},cn=policies;0]",
        },
        "rbcd": {
            "kind": "rbcd",
            "status": "pending",
            "target": "CN=C,DC=corp,DC=test",
            "previous": ["0102"],
        },
        "template-mod": {
            "kind": "template-mod",
            "status": "pending",
            "target": "CN=F,CN=Templates",
            "artifact": str(template),
        },
        "shadow-creds": {
            "kind": "shadow-creds",
            "status": "pending",
            "target": "CN=B,DC=corp,DC=test",
            "artifact": str(keycred),
        },
    }


@pytest.mark.parametrize("kind", ["acl", "gpo-link", "rbcd", "template-mod", "shadow-creds"])
def test_execute_cleanup_reverts_ldap_kind(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _Conn()
    monkeypatch.setattr(cleanup, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    _write_cleanup(tmp_path, _ldap_revertable_entries(tmp_path)[kind])
    result = cleanup.execute_cleanup(tmp_path, _target())
    assert result["completed"] == 1, result
    assert conn.modifies, f"{kind}: no reversal LDAP modify was issued"


def test_execute_cleanup_reverts_gpo_sysvol(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _Conn()
    monkeypatch.setattr(cleanup, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    deleted: list[tuple[str, str]] = []

    class _Smb:
        def deleteFile(self, share: str, path: str) -> None:
            deleted.append((share, path))

        def logoff(self) -> None:
            return None

    monkeypatch.setattr(gpo_sysvol, "_smb_connect", lambda target, host: _Smb())
    _write_cleanup(
        tmp_path,
        {
            "kind": "gpo-sysvol",
            "status": "pending",
            "target": "corp/Policies/{GUID}/Machine/adaf_staged.xml",
            "host": "dc.corp.test",
        },
    )
    result = cleanup.execute_cleanup(tmp_path, _target())
    assert result["completed"] == 1, result
    assert deleted == [("SYSVOL", r"corp\Policies\{GUID}\Machine\adaf_staged.xml")]


def test_advisory_kinds_are_not_auto_reverted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = _Conn()
    monkeypatch.setattr(cleanup, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    for kind, classification in _CAPABILITY_ROLLBACK.values():
        if classification != "advisory":
            continue
        _write_cleanup(tmp_path, {"kind": kind, "status": "pending", "target": "n/a"})
        result = cleanup.execute_cleanup(tmp_path, _target())
        assert result["completed"] == 0, f"{kind} was auto-reverted but is advisory"
        assert not conn.modifies, f"{kind} issued an LDAP modify but is advisory"


def test_revertable_classifications_match_engine() -> None:
    """Every 'revertable' capability kind must actually be reverted by the engine."""
    tested_ldap = {"acl", "gpo-link", "rbcd", "template-mod", "shadow-creds"}
    revertable = {kind for kind, cls in _CAPABILITY_ROLLBACK.values() if cls == "revertable"}
    # gpo-sysvol is proven in its own SMB-backed test above.
    assert revertable == tested_ldap | {"gpo-sysvol"}, revertable


def test_matrix_covers_exactly_the_destructive_capabilities_with_rollback() -> None:
    """The classification map must list exactly the destructive caps that wire rollback."""
    with_rollback: set[str] = set()
    for cap in capability_registry.list():
        if not cap.destructive:
            continue
        module = inspect.getmodule(type(cap.runner))
        assert module is not None
        source = inspect.getsource(module)
        if any(token in source for token in _ROLLBACK_PRIMITIVES):
            with_rollback.add(cap.id)
    assert set(_CAPABILITY_ROLLBACK) == with_rollback, {
        "missing_from_map": sorted(with_rollback - set(_CAPABILITY_ROLLBACK)),
        "stale_in_map": sorted(set(_CAPABILITY_ROLLBACK) - with_rollback),
    }
