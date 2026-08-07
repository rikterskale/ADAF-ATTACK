"""Offline end-to-end tests for directory enumeration capabilities."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import adaf_attack.capabilities.ldap_enum as ldap_enum
import adaf_attack.capabilities.rbcd as rbcd
from adaf_attack.core.acl import InterestingAce
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Attr:
    def __init__(self, value: Any = None) -> None:
        self.value = value
        self.raw_values = (
            value if isinstance(value, list) else ([value] if value is not None else [])
        )

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
        return self._attributes.get(name, self._attributes.get(name.replace("-", "_"), _Attr()))

    def __getitem__(self, name: str) -> _Attr:
        return self.__getattr__(name)


class _Connection:
    def __init__(self, responses: dict[str, list[_Entry]]) -> None:
        self.responses = responses
        self.entries: list[_Entry] = []
        self.unbound = False

    def search(self, base_dn: str, search_filter: str, **kwargs: Any) -> None:
        self.entries = self.responses.get(search_filter, [])

    def unbind(self) -> None:
        self.unbound = True


def _target() -> Target:
    return Target(domain="corp.test", dc_ip="192.0.2.10")


def test_ldap_enum_records_directory_relationships_and_artifacts(
    monkeypatch: Any, tmp_path: Path
) -> None:
    user = _Entry(
        sAMAccountName="alice",
        distinguishedName="CN=Alice,DC=corp,DC=test",
        userAccountControl=ldap_enum.UAC_DONT_REQ_PREAUTH | ldap_enum.UAC_TRUSTED_FOR_DELEGATION,
        servicePrincipalName=["HTTP/app.corp.test"],
        sidHistory=["S-1-5-21-999"],
        msDS_AllowedToDelegateTo=["cifs/dc01.corp.test"],
        memberOf=["CN=Domain Admins,DC=corp,DC=test"],
        adminCount=1,
    )
    computer = _Entry(
        sAMAccountName="DC01$",
        distinguishedName="CN=DC01,DC=corp,DC=test",
        dNSHostName="dc01.corp.test",
        operatingSystem="Windows Server",
        userAccountControl=ldap_enum.UAC_TRUSTED_FOR_DELEGATION,
        msDS_AllowedToDelegateTo=["ldap/dc01.corp.test"],
        servicePrincipalName=["HOST/dc01.corp.test"],
    )
    group = _Entry(
        sAMAccountName="Domain Admins",
        distinguishedName="CN=Domain Admins,DC=corp,DC=test",
        adminCount=1,
    )
    trust = _Entry(name="child", trustPartner="child.corp.test", trustDirection=3, trustType=2)
    gpo = _Entry(
        cn="{GPO-1}",
        displayName="Baseline",
        distinguishedName="CN={GPO-1},DC=corp,DC=test",
        gPCFileSysPath="\\\\corp.test\\SYSVOL\\corp.test\\Policies\\{GPO-1}",
        flags=0,
    )
    conn = _Connection(
        {
            ldap_enum.USER_FILTER: [user],
            ldap_enum.COMPUTER_FILTER: [computer],
            ldap_enum.GROUP_FILTER: [group],
            ldap_enum.TRUST_FILTER: [trust],
            ldap_enum.GPO_FILTER: [gpo],
        }
    )
    monkeypatch.setattr(ldap_enum, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    session = Session(tmp_path)
    graph = AttackGraph()

    result = ldap_enum.LdapEnum().run(_target(), session, graph)

    assert [item["sam"] for item in result["users"]] == ["alice"]
    assert result["spns"] == [{"account": "alice", "spn": "HTTP/app.corp.test"}]
    assert len(result["delegation"]) == 4
    assert result["sid_history"] == [{"account": "alice", "sid": "S-1-5-21-999"}]
    assert result["gpos"][0]["display_name"] == "Baseline"
    assert conn.unbound is True
    assert {edge.kind for edge in graph.edges} >= {
        "AllowedToDelegate",
        "CanASREP",
        "HasSIDHistory",
        "HasSPN",
        "MemberOf",
        "TrustedBy",
        "UnconstrainedDelegation",
    }
    assert json.loads(session.path("ldap-enum.json").read_text(encoding="utf-8")) == result


def test_rbcd_enum_reports_existing_and_writable_surfaces_without_force(
    monkeypatch: Any, tmp_path: Path
) -> None:
    configured = _Entry(
        sAMAccountName="WEB01$",
        distinguishedName="CN=WEB01,DC=corp,DC=test",
        dNSHostName="web01.corp.test",
        msDS_AllowedToActOnBehalfOfOtherIdentity="S-1-5-21-100 S-1-5-21-200",
    )
    writable = _Entry(sAMAccountName="APP01$", distinguishedName="CN=APP01,DC=corp,DC=test")
    conn = _Connection(
        {
            f"(&(objectClass=computer)({rbcd.ATTR}=*))": [configured],
            "(objectClass=computer)": [writable],
        }
    )
    monkeypatch.setattr(rbcd, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(rbcd, "fetch_sd", lambda connection, dn: b"descriptor")
    monkeypatch.setattr(
        rbcd,
        "parse_interesting_aces",
        lambda sd: [
            InterestingAce("S-1-5-21-300", "WriteDacl"),
            InterestingAce("S-1-5-21-400", "ReadProperty"),
        ],
    )
    session = Session(tmp_path)
    graph = AttackGraph()

    result = rbcd.Rbcd().run(_target(), session, graph, set_on="APP01$")

    assert result["rbcd_configured"][0]["allowed_to_act_sids"] == ["S-1-5-21-100", "S-1-5-21-200"]
    assert result["writable_computers"] == [
        {
            "computer": "APP01$",
            "dn": "CN=APP01,DC=corp,DC=test",
            "principal_sid": "S-1-5-21-300",
            "right": "WriteDacl",
        }
    ]
    assert result["set_attempt"] == {"set_on": "APP01$", "skipped": "force_required"}
    assert conn.unbound is True
    assert {edge.kind for edge in graph.edges} == {"AllowedToAct", "WriteRBCD"}
    assert json.loads(session.path("rbcd.json").read_text(encoding="utf-8")) == result


def test_rbcd_force_requires_controlled_source_computer(monkeypatch: Any, tmp_path: Path) -> None:
    conn = _Connection(
        {
            f"(&(objectClass=computer)({rbcd.ATTR}=*))": [],
            "(objectClass=computer)": [],
        }
    )
    monkeypatch.setattr(rbcd, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    result = rbcd.Rbcd().run(
        _target(), Session(tmp_path), AttackGraph(), force=True, set_on="APP01$"
    )

    assert result["set_attempt"] == {
        "set_on": "APP01$",
        "ok": False,
        "error": "set_from (controlled computer SAM) required",
    }
    assert conn.unbound
