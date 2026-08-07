"""Offline end-to-end coverage for gMSA/LAPS enumeration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import adaf_attack.capabilities.gmsa_laps_enum as gmsa
from adaf_attack.core.acl import InterestingAce
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Attr:
    def __init__(self, value: Any = None) -> None:
        self.value = value

    def __bool__(self) -> bool:
        return self.value is not None

    def __str__(self) -> str:
        return str(self.value)


class _Entry:
    def __init__(self, **values: Any) -> None:
        self.values = {key: _Attr(value) for key, value in values.items()}

    def __getattr__(self, name: str) -> _Attr:
        return self.values.get(name, self.values.get(name.replace("-", "_"), _Attr()))

    def __getitem__(self, name: str) -> _Attr:
        return self.__getattr__(name)


class _Connection:
    def __init__(self) -> None:
        self.entries: list[_Entry] = []
        self.unbound = False

    def search(self, base_dn: str, query: str, **kwargs: Any) -> None:
        if query == gmsa.GMSA_FILTER:
            self.entries = [
                _Entry(
                    sAMAccountName="sqlsvc$",
                    distinguishedName="CN=sqlsvc,DC=corp,DC=test",
                    msDS_ManagedPasswordInterval=30,
                    msDS_GroupMSAMembership="membership",
                )
            ]
        else:
            self.entries = [
                _Entry(
                    sAMAccountName="WEB01$",
                    distinguishedName="CN=WEB01,DC=corp,DC=test",
                    ms_Mcs_AdmPwd="hidden",
                )
            ]

    def unbind(self) -> None:
        self.unbound = True


def test_gmsa_laps_enum_records_inventory_acl_signals_and_graph_nodes(
    monkeypatch: Any, tmp_path: Path
) -> None:
    conn = _Connection()
    monkeypatch.setattr(gmsa, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(gmsa, "fetch_sd", lambda connection, dn: b"descriptor")
    monkeypatch.setattr(
        gmsa,
        "parse_interesting_aces",
        lambda sd: [InterestingAce("S-1-5-21-100", "ReadProperty")],
    )
    graph = AttackGraph()
    result = gmsa.GmsaLapsEnum().run(
        Target(domain="corp.test", dc_ip="192.0.2.10"), Session(tmp_path), graph
    )

    assert result["gmsa_count"] == 1
    assert result["laps_computer_count"] == 1
    assert result["secrets_returned"] == 0
    assert result["gmsas"][0]["acl_read_signals"] == ["S-1-5-21-100:ReadProperty"]
    assert result["laps_computers"][0]["legacy_laps"] is True
    assert conn.unbound is True
    assert {edge.kind for edge in graph.edges} == {"LAPSReadable"}
