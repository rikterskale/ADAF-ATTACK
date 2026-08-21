"""Branch-closure tests (batch 1) for LDAP-backed capabilities."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import adaf_attack.capabilities.delegation_ops as delegation_ops
import adaf_attack.capabilities.dmsa_ops as dmsa_ops
import adaf_attack.capabilities.gpo_abuse as gpo_abuse
import adaf_attack.capabilities.gpo_link as gpo_link
import adaf_attack.capabilities.gpo_sysvol as gpo_sysvol
import adaf_attack.capabilities.identity_bridge as identity_bridge
import adaf_attack.capabilities.ldap_enum as ldap_enum
import adaf_attack.capabilities.pkinit_auth as pkinit_auth
import adaf_attack.capabilities.rbcd as rbcd
import adaf_attack.capabilities.rodc_delegation as rodc_delegation
import adaf_attack.capabilities.shadow_creds as shadow_creds
from adaf_attack.core.acl import InterestingAce
from adaf_attack.core.graph import AttackGraph
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
        self,
        by_filter: dict[str, list[_Entry]] | None = None,
        *,
        modify_ok: bool = True,
        add_ok: bool = True,
    ) -> None:
        self.by_filter = by_filter or {}
        self.entries: list[_Entry] = []
        self.result: dict[str, Any] = {"result": 0, "description": "success"}
        self.modify_ok = modify_ok
        self.add_ok = add_ok
        self.unbound = False

    def search(self, base: str, search_filter: str, **kwargs: Any) -> bool:
        for key, entries in self.by_filter.items():
            if key in search_filter or key in base:
                self.entries = entries
                return True
        self.entries = []
        return True

    def modify(self, dn: str, changes: Any) -> bool:
        return self.modify_ok

    def add(self, dn: str, attributes: Any = None) -> bool:
        return self.add_ok

    def unbind(self) -> None:
        self.unbound = True


def _target(**kwargs: Any) -> Target:
    values = {"domain": "corp.test", "dc_ip": "10.0.0.1"}
    values.update(kwargs)
    return Target(**values)


def test_constrained_delegation_modify_failure_skips_rollback(
    monkeypatch: Any, tmp_path: Path
) -> None:
    svc = _Entry(sAMAccountName="svc", distinguishedName="CN=svc,DC=corp,DC=test")
    conn = _Conn({"sAMAccountName=svc": [svc]}, modify_ok=False)
    monkeypatch.setattr(delegation_ops, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    result = delegation_ops.ConstrainedDelegation().run(
        _target(), Session(tmp_path), AttackGraph(), force=True, sam="svc", spn="cifs/app"
    )
    assert result["set_attempt"]["ok"] is False


def test_dmsa_create_failure_and_unparsed_managed_password(
    monkeypatch: Any, tmp_path: Path
) -> None:
    krbtgt = _Entry(sAMAccountName="krbtgt", distinguishedName="CN=krbtgt,DC=corp,DC=test")
    conn = _Conn({"sAMAccountName=krbtgt": [krbtgt]}, add_ok=False)
    monkeypatch.setattr(dmsa_ops, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    result = dmsa_ops.BadSuccessor().run(
        _target(), Session(tmp_path), AttackGraph(), force=True, preceded_by="krbtgt"
    )
    assert result["ok"] is False

    holder = _Entry(**{"msDS-ManagedPassword": b"short"})
    conn2 = _Conn({"objectClass=*": [holder]})
    secret = dmsa_ops._read_managed_password(conn2, "CN=x", True)
    assert secret == {"present": True, "blob_len": 5}


def test_gpo_abuse_non_writer_ace_and_deep_ou_link(monkeypatch: Any, tmp_path: Path) -> None:
    gpo = _Entry(
        cn="{GPO-1}",
        displayName="Baseline",
        distinguishedName="CN={GPO-1},DC=corp,DC=test",
        gPCFileSysPath="\\\\corp.test\\SYSVOL\\corp.test\\Policies\\{GPO-1}",
        flags=0,
        versionNumber=12,
    )
    link = _Entry(
        distinguishedName="OU=Deep,OU=Nest,DC=corp,DC=test",
        gPLink="[LDAP://CN={GPO-1},CN=Policies,CN=System,DC=corp,DC=test;0]",
        name="Deep",
    )

    class _SeqConn:
        def __init__(self) -> None:
            self.entries: list[Any] = []
            self.unbound = False

        def search(self, base: str, search_filter: str, **kwargs: Any) -> None:
            if "groupPolicyContainer" in search_filter:
                self.entries = [gpo]
            else:
                self.entries = [link]

        def unbind(self) -> None:
            self.unbound = True

    conn = _SeqConn()
    monkeypatch.setattr(gpo_abuse, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(gpo_abuse, "fetch_sd", lambda c, dn: b"sd")
    monkeypatch.setattr(
        gpo_abuse,
        "parse_interesting_aces",
        lambda sd: [
            InterestingAce("S-1-5-21-100", "Self"),
            InterestingAce("S-1-5-21-9", "WriteDacl"),
        ],
    )
    result = gpo_abuse.GpoAbuse().run(_target(), Session(tmp_path), AttackGraph())
    assert result["writable_gpos"][0]["link_count"] == 1
    assert result["writable_gpos"][0]["writers"] == [{"sid": "S-1-5-21-9", "right": "WriteDacl"}]
    assert result["links"][0]["is_domain"] is False


def test_gpo_link_modify_failure_skips_cleanup(monkeypatch: Any, tmp_path: Path) -> None:
    entry = SimpleNamespace(gPLink="[LDAP://CN=old;0]")
    conn = SimpleNamespace(
        entries=[entry],
        result={"result": 0},
        search=lambda *a, **k: None,
        modify=lambda dn, changes: False,
        unbind=lambda: None,
    )
    monkeypatch.setattr(gpo_link, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    session = Session(tmp_path)
    result = gpo_link.GpoLink().run(
        _target(),
        session,
        AttackGraph(),
        force=True,
        write_target="OU=X,DC=corp,DC=test",
        value="[LDAP://CN=new;0]",
    )
    assert result["ok"] is False
    assert session.path("gpo-link.json").is_file()


def test_gpo_sysvol_non_writing_ace_right_is_ignored(monkeypatch: Any, tmp_path: Path) -> None:
    entry = SimpleNamespace(
        cn="{GPO-1}",
        displayName="Baseline",
        gPCFileSysPath="\\\\corp.test\\SYSVOL\\corp.test\\Policies\\{GPO-1}",
        distinguishedName="CN={GPO-1},DC=corp,DC=test",
    )
    conn = SimpleNamespace(entries=[entry], unbind=lambda: None)

    def fake_search(base_dn: str, search_filter: str, **kwargs: Any) -> None:
        conn.entries = [entry]

    conn.search = fake_search
    monkeypatch.setattr(gpo_sysvol, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(gpo_sysvol, "fetch_sd", lambda connection, dn: b"descriptor")
    monkeypatch.setattr(
        gpo_sysvol,
        "parse_interesting_aces",
        lambda sd: [InterestingAce("S-1-5-21-100", "CreateChild")],
    )
    result = gpo_sysvol.GpoSysvol().run(_target(), Session(tmp_path), AttackGraph())
    assert result["gpos"][0]["ldap_writers"] == []


def test_hybrid_signals_zero_recipient_details(monkeypatch: Any, tmp_path: Path) -> None:
    zero_details = SimpleNamespace(
        sAMAccountName=_Attr("bob"),
        msExchRecipientTypeDetails=_Attr(0),
    )
    conn = SimpleNamespace(
        entries=[zero_details],
        unbind=lambda: None,
        search=lambda *a, **k: None,
    )
    monkeypatch.setattr(identity_bridge, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    result = identity_bridge.HybridSignals().run(
        _target(), Session(tmp_path / "hybrid"), AttackGraph()
    )
    assert result["posture"]["synced_or_exchange_hybrid"] == 0
    assert all(s["signal"] != "ExchangeRecipientDetails" for s in result["signals"])


def test_ldap_enum_computer_without_unconstrained_and_trust_without_partner(
    monkeypatch: Any, tmp_path: Path
) -> None:
    user = _Entry(sAMAccountName="alice", distinguishedName="CN=Alice,DC=corp,DC=test")
    computer = _Entry(sAMAccountName="WS01$", distinguishedName="CN=WS01,DC=corp,DC=test")
    group = _Entry(sAMAccountName="Admins", distinguishedName="CN=Admins,DC=corp,DC=test")
    trust = _Entry(name="partner.local")
    conn = _Conn(
        {
            "objectCategory=person": [user],
            "objectCategory=computer": [computer],
            "objectCategory=group": [group],
            "trustedDomain": [trust],
        }
    )
    monkeypatch.setattr(ldap_enum, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    result = ldap_enum.LdapEnum().run(_target(), Session(tmp_path), AttackGraph())
    assert result["computers"][0]["unconstrained_delegation"] is False
    assert result["trusts"][0]["partner"] is None


def test_rodc_delegation_rbcd_only_entry_has_no_delegation_edges(
    monkeypatch: Any, tmp_path: Path
) -> None:
    rbcd_only = _Entry(
        sAMAccountName="SVC01",
        distinguishedName="CN=SVC01,DC=corp,DC=test",
        **{"msDS-AllowedToActOnBehalfOfOtherIdentity": b"\x01\x02"},
    )

    class _RodcConn:
        def __init__(self) -> None:
            self.entries: list[Any] = []
            self.unbound = False

        def search(self, base: str, query: str, **kwargs: Any) -> None:
            if "67108864" in query or "krbtgt_" in query:
                self.entries = []
            else:
                self.entries = [rbcd_only]

        def unbind(self) -> None:
            self.unbound = True

    monkeypatch.setattr(rodc_delegation, "ldap_connect", lambda t: (_RodcConn(), "DC=x", None))
    graph = AttackGraph()
    result = rodc_delegation.RodcDelegation().run(_target(), Session(tmp_path), graph)
    assert result["delegation"][0]["has_rbcd_attribute"] is True
    assert not any(edge.kind == "UnconstrainedDelegation" for edge in graph.edges)
    assert not any(edge.kind == "AllowedToDelegate" for edge in graph.edges)


def test_shadow_creds_enum_ignores_non_keycred_rights(monkeypatch: Any, tmp_path: Path) -> None:
    entry = _Entry(sAMAccountName="krbtgt", distinguishedName="CN=krbtgt,DC=corp,DC=test")

    class _ShadowConn:
        def __init__(self) -> None:
            self.entries: list[Any] = [entry]
            self.unbound = False

        def search(self, base: str, query: str, **kwargs: Any) -> None:
            self.entries = [entry]

        def unbind(self) -> None:
            self.unbound = True

    conn = _ShadowConn()
    monkeypatch.setattr(shadow_creds, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(shadow_creds, "fetch_sd", lambda c, dn: b"sd")
    monkeypatch.setattr(
        shadow_creds,
        "parse_interesting_aces",
        lambda sd: [InterestingAce("S-1-5-21-500", "ListObject")],
    )
    result = shadow_creds.ShadowCreds().run(_target(), Session(tmp_path), AttackGraph())
    assert result["writable_principals"] == []


def test_find_shadow_artifacts_key_without_cert_falls_through(tmp_path: Path) -> None:
    session = Session(tmp_path)
    session.path("shadow-a.key.pem").write_bytes(b"key")
    found = pkinit_auth._find_shadow_artifacts(session, None)
    assert found["key"] is None and found["cert"] is None
    assert pkinit_auth._find_shadow_artifacts(session, "")["key"] is None


def _rbcd_conn() -> _Conn:
    app01 = _Entry(
        sAMAccountName="APP01$",
        distinguishedName="CN=APP01,DC=corp,DC=test",
        objectSid="S-1-5-21-1-2-3-1105",
    )
    web01 = _Entry(
        sAMAccountName="WEB01$",
        distinguishedName="CN=WEB01,DC=corp,DC=test",
        objectSid="S-1-5-21-1-2-3-1106",
    )
    prev = _Entry(**{rbcd.ATTR: [b"\x01\x02"]})
    return _Conn(
        {
            f"{rbcd.ATTR}=*": [],
            "msDS-AllowedToDelegateTo=*": [],
            "(objectClass=computer)": [app01],
            "(sAMAccountName=APP01)": [],
            "(sAMAccountName=APP01$)": [app01],
            "(sAMAccountName=WEB01$)": [web01],
            "CN=APP01": [prev],
        }
    )


def test_rbcd_set_with_write_evidence_and_candidate_fallback(
    monkeypatch: Any, tmp_path: Path
) -> None:
    conn = _rbcd_conn()
    monkeypatch.setattr(rbcd, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(rbcd, "fetch_sd", lambda c, dn: b"sd")
    monkeypatch.setattr(
        rbcd, "parse_interesting_aces", lambda sd: [InterestingAce("S-1-5-21-1", "GenericAll")]
    )
    result = rbcd.Rbcd().run(
        _target(), Session(tmp_path), AttackGraph(), force=True, set_on="APP01", set_from="WEB01$"
    )
    assert result["set_attempt"]["ok"] is True
    assert result["set_attempt"]["set_from_sid"].startswith("S-1-5-21-1")


def test_rbcd_set_target_lookup_exhausts_candidates(monkeypatch: Any, tmp_path: Path) -> None:
    conn = _rbcd_conn()
    monkeypatch.setattr(rbcd, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(rbcd, "fetch_sd", lambda c, dn: None)
    result = rbcd.Rbcd().run(
        _target(), Session(tmp_path), AttackGraph(), force=True, set_on="ZZZ", set_from="WEB01$"
    )
    assert result["set_attempt"]["ok"] is False
    assert "lookup failed" in result["set_attempt"]["error"]
