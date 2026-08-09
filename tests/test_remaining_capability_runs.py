"""Offline execution tests for previously untested capability modules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import adaf_attack.capabilities.asrep_roast as asrep_roast
import adaf_attack.capabilities.computer_takeover as computer_takeover
import adaf_attack.capabilities.gpo_abuse as gpo_abuse
import adaf_attack.capabilities.gpo_link as gpo_link
import adaf_attack.capabilities.kerberoast as kerberoast
import adaf_attack.capabilities.rodc_delegation as rodc_delegation
import adaf_attack.capabilities.trusts_enum as trusts_enum
from adaf_attack.core.acl import InterestingAce
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Attr:
    def __init__(self, value: Any = None) -> None:
        self.value = value

    def __bool__(self) -> bool:
        return self.value is not None and self.value != []

    def __iter__(self) -> Any:
        return iter(self.value if isinstance(self.value, list) else [])

    def __str__(self) -> str:
        return str(self.value)


class _Entry:
    def __init__(self, **attributes: Any) -> None:
        self._attributes = {name: _Attr(value) for name, value in attributes.items()}

    def __getattr__(self, name: str) -> _Attr:
        return self._attributes.get(name, _Attr())

    def __getitem__(self, name: str) -> _Attr:
        return self.__getattr__(name)


class _Connection:
    def __init__(self, responses: dict[str, list[_Entry]]) -> None:
        self.responses = responses
        self.entries: list[_Entry] = []
        self.result = {"description": "success"}
        self.modified: tuple[str, dict[str, Any]] | None = None
        self.unbound = False

    def search(self, _base: str, query: str, **_kwargs: Any) -> None:
        self.entries = self.responses.get(query, [])

    def modify(self, dn: str, changes: dict[str, Any]) -> bool:
        self.modified = (dn, changes)
        return True

    def unbind(self) -> None:
        self.unbound = True


def _target() -> Target:
    return Target(domain="corp.test", dc_ip="192.0.2.10")


def test_computer_takeover_discovers_writable_identity_and_records_change(
    monkeypatch: Any, tmp_path: Path
) -> None:
    computer = _Entry(sAMAccountName="WEB01$", distinguishedName="CN=WEB01,DC=corp,DC=test")
    conn = _Connection(
        {"(objectClass=computer)": [computer], "(sAMAccountName=WEB01$)": [computer]}
    )
    monkeypatch.setattr(
        computer_takeover, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None)
    )
    monkeypatch.setattr(computer_takeover, "fetch_sd", lambda conn, dn: b"sd")
    monkeypatch.setattr(
        computer_takeover,
        "parse_interesting_aces",
        lambda sd: [InterestingAce("S-1-5-21-1", "GenericWrite")],
    )
    session = Session(tmp_path)
    graph = AttackGraph()

    result = computer_takeover.ComputerTakeover().run(
        _target(),
        session,
        graph,
        force=True,
        write_target="WEB01$",
        attribute="dNSHostName",
        value="owned.corp.test",
    )

    assert result["count"] == 1
    assert result["change"] == {
        "target": "CN=WEB01,DC=corp,DC=test",
        "attribute": "dNSHostName",
        "ok": True,
    }
    assert conn.modified is not None and conn.unbound
    assert graph.edges[0].kind == "WriteComputerIdentity"
    assert json.loads(session.path("computer-takeover.json").read_text()) == result
    assert json.loads(session.path("cleanup.json").read_text())[0]["kind"] == "computer-identity"


@pytest.mark.parametrize("kwargs", [{}, {"force": True, "write_target": "OU=Ops"}])
def test_gpo_link_requires_complete_force_gated_input(
    kwargs: dict[str, Any], tmp_path: Path
) -> None:
    with pytest.raises(RuntimeError, match="gpo-link requires"):
        gpo_link.GpoLink().run(_target(), Session(tmp_path), AttackGraph(), **kwargs)


def test_gpo_link_updates_and_registers_rollback(monkeypatch: Any, tmp_path: Path) -> None:
    dn = "OU=Ops,DC=corp,DC=test"
    conn = _Connection({"(objectClass=*)": [_Entry(gPLink="[LDAP://old;0]")]})
    monkeypatch.setattr(gpo_link, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    session = Session(tmp_path)

    result = gpo_link.GpoLink().run(
        _target(), session, AttackGraph(), force=True, write_target=dn, value="[LDAP://new;0]"
    )

    assert result["ok"] is True and conn.unbound
    assert conn.modified is not None
    assert json.loads(session.path("cleanup.json").read_text())[0]["previous"] == "[LDAP://old;0]"
    assert json.loads(session.path("gpo-link.json").read_text()) == result


def test_rodc_delegation_reports_rodc_and_delegation(monkeypatch: Any, tmp_path: Path) -> None:
    conn = _Connection(
        {
            "(&(objectClass=user)(sAMAccountName=krbtgt_*))": [
                _Entry(sAMAccountName="krbtgt_123", distinguishedName="CN=krbtgt_123")
            ],
            "(|(objectClass=user)(objectClass=computer))": [
                _Entry(
                    sAMAccountName="APP01$",
                    userAccountControl=0x80000,
                    **{"msDS-AllowedToDelegateTo": ["cifs/dc01"]},
                )
            ],
        }
    )
    monkeypatch.setattr(
        rodc_delegation, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None)
    )
    session = Session(tmp_path)
    graph = AttackGraph()

    result = rodc_delegation.RodcDelegation().run(_target(), session, graph)

    assert result["count"] == 2 and result["delegation"][0]["unconstrained"] is True
    assert graph.edges[0].kind == "UnconstrainedDelegation"
    assert conn.unbound
    assert json.loads(session.path("rodc-delegation.json").read_text()) == result


def test_gpo_abuse_reports_writable_gpos_and_links(monkeypatch: Any, tmp_path: Path) -> None:
    gpo = _Entry(
        cn="{GPO-1}",
        displayName="Baseline",
        distinguishedName="CN={GPO-1},DC=corp,DC=test",
        gPCFileSysPath="\\\\corp.test\\SYSVOL\\baseline",
        flags=0,
        versionNumber=3,
    )
    link = _Entry(
        distinguishedName="OU=Ops,DC=corp,DC=test",
        name="Ops",
        gPLink="[LDAP://CN={GPO-1},DC=corp,DC=test;0]",
    )
    conn = _Connection(
        {
            "(objectClass=groupPolicyContainer)": [gpo],
            "(|(objectClass=organizationalUnit)(objectClass=domainDNS))": [link],
        }
    )
    monkeypatch.setattr(gpo_abuse, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(gpo_abuse, "fetch_sd", lambda conn, dn: b"sd")
    monkeypatch.setattr(
        gpo_abuse,
        "parse_interesting_aces",
        lambda sd: [InterestingAce("S-1-5-21-2", "WriteDacl")],
    )
    session = Session(tmp_path)
    graph = AttackGraph()

    result = gpo_abuse.GpoAbuse().run(_target(), session, graph)

    assert result["writable_gpos"][0]["writers"][0]["right"] == "WriteDacl"
    assert result["links"][0]["name"] == "Ops"
    assert {edge.kind for edge in graph.edges} == {"WriteGPO", "GPLink"}
    assert conn.unbound


def test_trusts_enum_identifies_inbound_trust_without_sid_filtering(
    monkeypatch: Any, tmp_path: Path
) -> None:
    trust = _Entry(
        name="child",
        flatName="CHILD",
        trustPartner="child.corp.test",
        trustDirection=3,
        trustType=2,
        trustAttributes=0x80,
        distinguishedName="CN=child,CN=System,DC=corp,DC=test",
    )
    conn = _Connection({"(objectClass=trustedDomain)": [trust]})
    monkeypatch.setattr(trusts_enum, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    graph = AttackGraph()
    result = trusts_enum.TrustsEnum().run(_target(), Session(tmp_path), graph)

    assert result["inbound_without_sid_filter"] == ["child.corp.test"]
    assert "USES_RC4_ENCRYPTION" in result["trusts"][0]["attributes"]
    assert {edge.kind for edge in graph.edges} == {"TrustedBy", "ExternalTrust"}


def test_kerberoast_collects_hashes_without_contacting_a_kdc(
    monkeypatch: Any, tmp_path: Path
) -> None:
    from impacket.krb5 import kerberosv5

    account = _Entry(sAMAccountName="svc-web", servicePrincipalName=["HTTP/web.corp.test"])
    conn = _Connection(
        {"(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))": [account]}
    )
    monkeypatch.setattr(kerberoast, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(kerberoast, "get_kerberos_tgt", lambda target: (b"tgt", None, None, b"key"))
    monkeypatch.setattr(
        kerberoast, "format_tgs_hashcat", lambda spn, sam, domain, tgs: "$krb5tgs$23$hash"
    )
    monkeypatch.setattr(kerberosv5, "getKerberosTGS", lambda *args: (b"tgs", None, None, b"key"))
    session = Session(tmp_path)
    graph = AttackGraph()

    result = kerberoast.Kerberoast().run(
        Target(domain="corp.test", dc_ip="192.0.2.10", username="alice", password="secret"),
        session,
        graph,
        include_secrets=True,
    )

    assert result["count"] == 1 and result["tickets"][0]["format"] == "hashcat-13100"
    assert session.path("kerberoast.hashes.txt").read_text() == "$krb5tgs$23$hash\n"
    assert {edge.kind for edge in graph.edges} == {"HasSPN"}
    assert conn.unbound


def test_kerberoast_requires_credentials(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="requires credentials"):
        kerberoast.Kerberoast().run(_target(), Session(tmp_path), AttackGraph())


def test_asrep_roast_records_empty_candidate_set_offline(monkeypatch: Any, tmp_path: Path) -> None:
    conn = _Connection(
        {
            "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))": []
        }
    )
    monkeypatch.setattr(asrep_roast, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    session = Session(tmp_path)
    result = asrep_roast.AsrepRoast().run(_target(), session, AttackGraph())

    assert result == {"domain": "corp.test", "count": 0, "tickets": "[REDACTED]"}
    assert conn.unbound
    assert json.loads(session.path("asrep-roast.json").read_text()) == result


def test_asrep_roast_records_kdc_errors_without_network_side_effects(
    monkeypatch: Any, tmp_path: Path
) -> None:
    from impacket.krb5 import kerberosv5

    candidate = _Entry(sAMAccountName="legacy-user")
    conn = _Connection(
        {
            "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))": [
                candidate
            ]
        }
    )
    monkeypatch.setattr(asrep_roast, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(
        kerberosv5, "sendReceive", lambda *args: (_ for _ in ()).throw(OSError("KDC unavailable"))
    )

    result = asrep_roast.AsrepRoast().run(_target(), Session(tmp_path), AttackGraph())

    assert result["count"] == 1
    assert result["tickets"] == "[REDACTED]"
    assert conn.unbound
