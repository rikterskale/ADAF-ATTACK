"""Branch-closure tests for credential, spray, dns, relay, sccm, inventory, roast."""

from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from cryptography.fernet import Fernet

import adaf_attack.capabilities.credential_inventory as credential_inventory
import adaf_attack.capabilities.credential_ops as credential_ops
import adaf_attack.capabilities.dns_ops as dns_ops
import adaf_attack.capabilities.password_spray as password_spray
import adaf_attack.capabilities.relay_ops as relay_ops
import adaf_attack.capabilities.sccm_ops as sccm_ops
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.roast_format import _extract_cipher_and_etype
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Attr:
    def __init__(self, value: Any = None) -> None:
        self.value = value
        self.values = value if isinstance(value, list) else ([] if value is None else [value])
        self.raw_values = self.values

    def __bool__(self) -> bool:
        return self.value is not None and self.value != []

    def __str__(self) -> str:
        return str(self.value)


class _Entry:
    def __init__(self, **values: Any) -> None:
        self._values = {key: _Attr(value) for key, value in values.items()}

    def __getattr__(self, name: str) -> _Attr:
        if name in self._values:
            return self._values[name]
        alt = name.replace("_", "-")
        if alt in self._values:
            return self._values[alt]
        return _Attr()

    def __getitem__(self, name: str) -> _Attr:
        return self.__getattr__(name)


class _Conn:
    def __init__(
        self, by_filter: dict[str, list[_Entry]] | None = None, *, add_ok: bool = True
    ) -> None:
        self.by_filter = by_filter or {}
        self.entries: list[_Entry] = []
        self.result = {"result": 0, "description": "success"}
        self.add_ok = add_ok
        self.unbound = False

    def search(self, base: str, search_filter: str, **kwargs: Any) -> bool:
        for key, entries in self.by_filter.items():
            if key in search_filter or search_filter in key or key in base:
                self.entries = entries
                return True
        self.entries = []
        return True

    def add(self, dn: str, attributes: Any = None) -> bool:
        return self.add_ok

    def modify(self, dn: str, changes: Any = None) -> bool:
        return True

    def unbind(self) -> None:
        self.unbound = True


def _target(**kwargs: Any) -> Target:
    values = {
        "domain": "corp.test",
        "dc_ip": "10.0.0.1",
        "username": "alice",
        "password": "Secret1!",
        "ldaps": True,
    }
    values.update(kwargs)
    return Target(**values)


def _patch_ldap(monkeypatch: Any, module: Any, conn: _Conn, base: str = "DC=corp,DC=test") -> None:
    monkeypatch.setattr(
        module, "ldap_connect", lambda target: (conn, base, "CN=Configuration,DC=corp,DC=test")
    )


def _managed_blob_no_current() -> bytes:
    header = struct.pack("<HHI", 1, 0, 32)
    header += struct.pack("<HHHH", 0, 0, 0, 0)
    return header + b"\x00" * 16


def test_gmsa_read_parsed_without_current_password(monkeypatch: Any, tmp_path: Path) -> None:
    gmsa = _Entry(
        sAMAccountName="svc$",
        distinguishedName="CN=SVC,DC=corp,DC=test",
        **{"msDS-ManagedPassword": _managed_blob_no_current()},
    )
    conn = _Conn({"svc": [gmsa]})
    _patch_ldap(monkeypatch, credential_ops, conn)
    result = credential_ops.GmsaRead().run(_target(), Session(tmp_path), AttackGraph(), sam="svc$")
    assert result["gmsas"][0]["parsed"] is True
    assert "managed_password" not in result["gmsas"][0]


def test_pre2k_spray_without_attempt_limit(monkeypatch: Any, tmp_path: Path) -> None:
    computer = _Entry(sAMAccountName="WS01$", distinguishedName="CN=WS01,DC=corp,DC=test")
    conn = _Conn({"objectClass=computer": [computer]})
    _patch_ldap(monkeypatch, credential_ops, conn)
    monkeypatch.setattr(credential_ops, "try_ntlm_bind", lambda *a, **k: (False, "no"))
    result = credential_ops.Pre2kSpray().run(_target(), Session(tmp_path), AttackGraph())
    assert result["attempt_count"] == 1 and result["hit_count"] == 0


def test_timeroast_short_response_and_no_secrets(monkeypatch: Any, tmp_path: Path) -> None:
    session = Session(tmp_path)
    graph = AttackGraph()
    monkeypatch.setattr(credential_ops, "_udp_query", lambda *a, **k: b"\x00" * 10)
    miss = credential_ops.Timeroast().run(_target(), session, graph, rid_start=1, rid_end=2)
    assert miss["count"] == 0
    monkeypatch.setattr(credential_ops, "_udp_query", lambda *a, **k: b"\x00" * 68)
    hit = credential_ops.Timeroast().run(_target(), session, graph, rid_start=3, rid_end=3)
    assert hit["count"] == 1 and "hash" not in hit["hashes"][0]


def _fake_conn(entries: list[Any]) -> Any:
    def _search(*args: Any, **kwargs: Any) -> None:
        return None

    return SimpleNamespace(entries=entries, search=_search)


def test_read_lockout_policy_empty_entries_and_missing_attrs() -> None:
    assert password_spray._read_lockout_policy(_fake_conn([]), "DC=corp,DC=test") == {
        "lockout_threshold": 0,
        "observation_window_seconds": 0,
    }
    no_threshold = SimpleNamespace(
        lockoutThreshold=None, lockoutObservationWindow=SimpleNamespace(value=50000000)
    )
    policy = password_spray._read_lockout_policy(_fake_conn([no_threshold]), "DC=corp,DC=test")
    assert policy == {"lockout_threshold": 0, "observation_window_seconds": 5}
    no_window = SimpleNamespace(lockoutThreshold=None, lockoutObservationWindow=None)
    assert (
        password_spray._read_lockout_policy(_fake_conn([no_window]), "DC=corp,DC=test")[
            "observation_window_seconds"
        ]
        == 0
    )


def test_load_users_skips_entries_without_sam() -> None:
    conn = _fake_conn([_Entry(sAMAccountName=""), _Entry(sAMAccountName="alice")])
    users = password_spray._load_users(None, conn, "DC=corp,DC=test", None)
    assert users == ["alice"]


def test_adidns_wpad_add_failure_skips_graph_edge(monkeypatch: Any, tmp_path: Path) -> None:
    conn = _Conn({"MicrosoftDNS": [_Entry(name="corp.test")]}, add_ok=False)
    _patch_ldap(monkeypatch, dns_ops, conn)
    result = dns_ops.AdidnsWpad().run(
        _target(), Session(tmp_path), AttackGraph(), force=True, ip="10.0.0.9"
    )
    assert result["ok"] is False


def test_dcshadow_add_failures_skip_rollbacks(monkeypatch: Any, tmp_path: Path) -> None:
    rogue = _Entry(
        sAMAccountName="ROGUE$",
        distinguishedName="CN=ROGUE,DC=corp,DC=test",
        dNSHostName="rogue.corp.test",
    )
    conn = _Conn({"ROGUE": [rogue]}, add_ok=False)
    _patch_ldap(monkeypatch, relay_ops, conn)
    result = relay_ops.DcShadow().run(
        _target(), Session(tmp_path), AttackGraph(), force=True, computer="ROGUE$"
    )
    assert result["ok"] is False and result["server_ok"] is False and result["ntds_ok"] is False


def test_sccm_enum_object_without_dns(monkeypatch: Any, tmp_path: Path) -> None:
    mp = _Entry(
        cn="MP",
        distinguishedName="CN=MP,CN=System Management,CN=System,DC=corp,DC=test",
        mSSMSSiteCode="P01",
        mSSMSMPName="mp.corp.test",
    )
    conn = _Conn({"System Management": [mp], "*": []})
    _patch_ldap(monkeypatch, sccm_ops, conn)
    result = sccm_ops.SccmEnum().run(_target(), Session(tmp_path), AttackGraph())
    assert result["count"] >= 1


def test_sccm_naa_no_secrets_and_no_signal(monkeypatch: Any, tmp_path: Path) -> None:
    mp = _Entry(
        cn="MP",
        distinguishedName="CN=MP,CN=System Management,CN=System,DC=corp,DC=test",
        dNSHostName="mp.corp.test",
    )
    conn = _Conn({"System Management": [mp], "*": []})
    _patch_ldap(monkeypatch, sccm_ops, conn)
    monkeypatch.setattr(sccm_ops, "_http_get", lambda url, timeout=5.0: (200, "nothing here"))
    result = sccm_ops.SccmNaa().run(_target(), Session(tmp_path), AttackGraph())
    hit = result["http_hits"][0]
    assert "body" not in hit and "naa_signal" not in hit


def _session(tmp_path: Path, monkeypatch: Any) -> Session:
    monkeypatch.setenv("ADAF_SESSION_VAULT_KEY", Fernet.generate_key().decode())
    return Session(tmp_path)


def test_vault_catalog_and_purge_branches(tmp_path: Path, monkeypatch: Any) -> None:
    session = _session(tmp_path / "session", monkeypatch)
    session.vault().put("counter", "aes-key", 12345, secret=True)
    rows = credential_inventory._vault_catalog(session, include_secrets=True)
    assert rows[0]["value_type"] == "int"
    removed = credential_inventory._purge(session, names=None, purge_all=True, purge_files=False)
    assert removed == {"removed_vault": ["*1 items*"], "removed_files": [], "purge_all": True}

    ghost = tmp_path / "ghost.bin"

    def _ghost_scan(_session: Session) -> list[dict[str, Any]]:
        return [{"path": str(ghost), "name": "ghost.bin"}]

    monkeypatch.setattr(credential_inventory, "_scan_artifacts", _ghost_scan)
    purged = credential_inventory._purge(session, names=None, purge_all=True, purge_files=True)
    assert purged["removed_files"] == []


class _NoComponent:
    pass


class _NoneComponents:
    def getComponentByName(self, name: str) -> None:
        return None


class _InnerCipherOnly:
    def getComponentByName(self, name: str) -> bytes | None:
        return b"x" * 24 if name == "cipher" else None


class _EncInnerCipherOnly:
    def getComponentByName(self, name: str) -> Any:
        return _InnerCipherOnly()


class _InnerEmpty:
    def getComponentByName(self, name: str) -> None:
        return None


class _EncInnerEmpty:
    def getComponentByName(self, name: str) -> Any:
        return _InnerEmpty()


class _EncPartScalar:
    def __init__(self) -> None:
        self.cipher = None
        self.etype = None

    def getComponentByName(self, name: str) -> None:
        return None


def test_extract_cipher_component_fallthrough_branches() -> None:
    assert _extract_cipher_and_etype(SimpleNamespace(encPart=None)) == (None, None)
    assert _extract_cipher_and_etype(_NoneComponents()) == (None, None)
    cipher, etype = _extract_cipher_and_etype(_EncInnerCipherOnly())
    assert cipher == b"x" * 24 and etype is None
    assert _extract_cipher_and_etype(_EncInnerEmpty()) == (None, None)
    ticket = SimpleNamespace(encPart=_EncPartScalar())
    assert _extract_cipher_and_etype(ticket) == (None, None)


def test_extract_cipher_encpart_without_component_lookup() -> None:
    class _BadEnc:
        def getComponentByName(self, name: str) -> Any:
            return _NoComponent()

    assert _extract_cipher_and_etype(_BadEnc()) == (None, None)


def test_gmsa_read_unparseable_blob_no_secrets(monkeypatch: Any, tmp_path: Path) -> None:
    gmsa = _Entry(
        sAMAccountName="svc$",
        distinguishedName="CN=SVC,DC=corp,DC=test",
        **{"msDS-ManagedPassword": "short"},
    )
    conn = _Conn({"svc": [gmsa]})
    _patch_ldap(monkeypatch, credential_ops, conn)
    result = credential_ops.GmsaRead().run(_target(), Session(tmp_path), AttackGraph(), sam="svc$")
    assert result["gmsas"][0]["managed_password_present"] is True
    assert "parsed" not in result["gmsas"][0]


def test_extract_cipher_inner_without_component_lookup() -> None:
    class _InnerWithLookupReturningPlain:
        def getComponentByName(self, name: str) -> Any:
            return _NoComponent()

    class _Outer:
        def __init__(self) -> None:
            self._enc = _InnerWithLookupReturningPlain()

        def getComponentByName(self, name: str) -> Any:
            return self._enc

    assert _extract_cipher_and_etype(_Outer()) == (None, None)
