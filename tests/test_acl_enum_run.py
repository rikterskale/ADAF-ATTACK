"""Offline end-to-end tests for ACL enumeration output and failure handling."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import adaf_attack.capabilities.acl_enum as acl_enum
from adaf_attack.core.acl import InterestingAce
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Connection:
    def __init__(self) -> None:
        self.unbound = False

    def unbind(self) -> None:
        self.unbound = True


def _target() -> Target:
    return Target(domain="corp.test", dc_ip="192.0.2.10")


def test_acl_enum_records_interesting_edges_dcsync_and_session_artifacts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    conn = _Connection()
    monkeypatch.setattr(acl_enum, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(
        acl_enum,
        "_sid_index",
        lambda connection, base_dn: {
            "S-1-5-21-1000": {
                "sam": "alice",
                "kind": "User",
                "dn": "CN=Alice,DC=corp,DC=test",
            }
        },
    )
    monkeypatch.setattr(
        acl_enum,
        "_high_value_targets",
        lambda connection, base_dn, domain: [
            ("DOMAIN@CORP.TEST", "DC=corp,DC=test", "Domain"),
            ("GROUP@DOMAIN ADMINS@CORP.TEST", "CN=Domain Admins,DC=corp,DC=test", "Group"),
        ],
    )
    monkeypatch.setattr(acl_enum, "fetch_sd", lambda connection, dn: b"security-descriptor")
    monkeypatch.setattr(
        acl_enum,
        "parse_interesting_aces",
        lambda sd: [
            InterestingAce("S-1-5-21-1000", "GetChanges"),
            InterestingAce("S-1-5-21-1000", "GetChangesAll"),
            InterestingAce("S-1-5-11", "ReadProperty"),
        ],
    )
    session = Session(tmp_path)
    graph = AttackGraph()

    result = acl_enum.AclEnum().run(_target(), session, graph)

    assert result["objects_scanned"] == 2
    assert result["interesting_edge_count"] == 4
    assert result["dcsync_principals"] == ["USER@ALICE@CORP.TEST"]
    assert conn.unbound is True
    assert {(edge.source, edge.target, edge.kind) for edge in graph.edges} >= {
        ("USER@ALICE@CORP.TEST", "DOMAIN@CORP.TEST", "GetChanges"),
        ("USER@ALICE@CORP.TEST", "DOMAIN@CORP.TEST", "GetChangesAll"),
        ("USER@ALICE@CORP.TEST", "DOMAIN@CORP.TEST", "DCSync"),
    }
    assert json.loads(session.path("acl-enum.json").read_text(encoding="utf-8")) == result
    assert json.loads(session.path("graph.json").read_text(encoding="utf-8"))["nodes"]


def test_acl_enum_unbinds_before_propagating_security_descriptor_parse_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    conn = _Connection()
    monkeypatch.setattr(acl_enum, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(acl_enum, "_sid_index", lambda connection, base_dn: {})
    monkeypatch.setattr(
        acl_enum,
        "_high_value_targets",
        lambda connection, base_dn, domain: [("DOMAIN@CORP.TEST", "DC=corp,DC=test", "Domain")],
    )
    monkeypatch.setattr(acl_enum, "fetch_sd", lambda connection, dn: b"invalid")
    monkeypatch.setattr(
        acl_enum, "parse_interesting_aces", lambda sd: (_ for _ in ()).throw(RuntimeError("bad sd"))
    )

    with pytest.raises(RuntimeError, match="bad sd"):
        acl_enum.AclEnum().run(_target(), Session(tmp_path), AttackGraph())

    assert conn.unbound is True


def test_acl_enum_keeps_scanning_when_a_mocked_descriptor_is_unparseable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    conn = _Connection()
    monkeypatch.setattr(acl_enum, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(acl_enum, "_sid_index", lambda connection, base_dn: {})
    monkeypatch.setattr(
        acl_enum,
        "_high_value_targets",
        lambda connection, base_dn, domain: [("DOMAIN@CORP.TEST", "DC=corp,DC=test", "Domain")],
    )
    monkeypatch.setattr(acl_enum, "fetch_sd", lambda connection, dn: b"malformed")
    monkeypatch.setattr(
        acl_enum,
        "parse_interesting_aces",
        lambda sd: (_ for _ in ()).throw(ValueError("mocked acl")),
    )
    assert (
        acl_enum.AclEnum().run(_target(), Session(tmp_path), AttackGraph())[
            "interesting_edge_count"
        ]
        == 0
    )
    assert conn.unbound is True
