"""Offline end-to-end test for SYSVOL GPO enumeration."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import adaf_attack.capabilities.gpo_sysvol as gpo_sysvol
from adaf_attack.core.acl import InterestingAce
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Connection:
    def __init__(self) -> None:
        self.entries: list[Any] = []
        self.unbound = False

    def search(self, base_dn: str, search_filter: str, **kwargs: Any) -> None:
        self.entries = [
            SimpleNamespace(
                cn="{GPO-1}",
                displayName="Baseline",
                gPCFileSysPath="\\\\corp.test\\SYSVOL\\corp.test\\Policies\\{GPO-1}",
                distinguishedName="CN={GPO-1},DC=corp,DC=test",
            )
        ]

    def unbind(self) -> None:
        self.unbound = True


def test_gpo_sysvol_records_ldap_writers_without_network_or_write_probe(
    monkeypatch: Any, tmp_path: Path
) -> None:
    conn = _Connection()
    monkeypatch.setattr(gpo_sysvol, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(gpo_sysvol, "fetch_sd", lambda connection, dn: b"descriptor")
    monkeypatch.setattr(
        gpo_sysvol,
        "parse_interesting_aces",
        lambda sd: [InterestingAce("S-1-5-21-100", "WriteDacl")],
    )
    session = Session(tmp_path)
    graph = AttackGraph()

    result = gpo_sysvol.GpoSysvol().run(
        Target(domain="corp.test", dc_ip="192.0.2.10"), session, graph
    )

    assert result["gpo_count"] == 1
    assert result["writable_sysvol_count"] == 0
    assert result["stage"] is None
    assert result["gpos"][0]["ldap_writers"] == [{"sid": "S-1-5-21-100", "right": "WriteDacl"}]
    assert conn.unbound is True
    assert {(edge.source, edge.kind) for edge in graph.edges} == {("SID@S-1-5-21-100", "WriteGPO")}
    assert json.loads(session.path("gpo-sysvol.json").read_text(encoding="utf-8")) == result
