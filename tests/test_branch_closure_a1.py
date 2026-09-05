"""Branch-closure tests for laps_read, maq_ops, trusts_enum, and gmsa_laps_enum."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import adaf_attack.capabilities.gmsa_laps_enum as gmsa
import adaf_attack.capabilities.laps_read as laps_read
import adaf_attack.capabilities.maq_ops as maq_ops
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

    def __str__(self) -> str:
        return str(self.value)


class _Entry:
    def __init__(self, **attributes: Any) -> None:
        self._attributes = {name: _Attr(value) for name, value in attributes.items()}

    def __getattr__(self, name: str) -> _Attr:
        return self._attributes.get(name.replace("-", "_"), self._attributes.get(name, _Attr()))

    def __getitem__(self, name: str) -> _Attr:
        return self.__getattr__(name)


class _Conn:
    def __init__(
        self,
        entries: list[_Entry] | None = None,
        *,
        add_ok: bool = True,
        modify_ok: bool = True,
    ) -> None:
        self.entries = entries or []
        self.result = {"result": 0, "description": "success"}
        self.add_ok = add_ok
        self.modify_ok = modify_ok
        self.unbound = False

    def search(self, base: str, query: str, **kwargs: Any) -> bool:
        return True

    def modify(self, dn: str, changes: Any) -> bool:
        return self.modify_ok

    def add(self, dn: str, attributes: Any = None) -> bool:
        return self.add_ok

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


def test_laps_read_skips_entries_without_password_attributes(
    monkeypatch: Any, tmp_path: Path
) -> None:
    entry = _Entry(sAMAccountName="BARE$", distinguishedName="CN=BARE,DC=corp,DC=test")
    conn = _Conn([entry])
    monkeypatch.setattr(laps_read, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    result = laps_read.LapsRead().run(_target(), Session(tmp_path), AttackGraph())

    assert result["count"] == 1
    assert result["v1_readable"] == 0 and result["v2_readable"] == 0
    assert result["entries"][0]["dns"] is None
    assert conn.unbound


def test_maq_computer_create_failure_records_nothing(monkeypatch: Any, tmp_path: Path) -> None:
    conn = _Conn(add_ok=False)
    monkeypatch.setattr(maq_ops, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    session = Session(tmp_path)
    graph = AttackGraph()

    created = maq_ops.MaqAddComputer().run(
        _target(), session, graph, force=True, computer="NEWPC", password="p"
    )
    assert created["ok"] is False
    assert not any(node.kind == "Computer" for node in graph.nodes.values())

    workflow = maq_ops.MaqRbcdWorkflow().run(_target(), session, graph, force=True, set_on="DC01$")
    assert workflow["ok"] is False
    assert workflow["rbcd"]["skipped"] == "computer_create_failed"


def test_maq_rbcd_workflow_skips_s4u_without_impersonate(monkeypatch: Any, tmp_path: Path) -> None:
    class _Rbcd:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"set_attempt": {"ok": True}}

    class _S4u:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ok": True}

    conn = _Conn()
    monkeypatch.setattr(maq_ops, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(maq_ops, "Rbcd", _Rbcd)
    monkeypatch.setattr(maq_ops, "S4uAbuse", _S4u)
    session = Session(tmp_path)

    result = maq_ops.MaqRbcdWorkflow().run(
        _target(), session, AttackGraph(), force=True, set_on="DC01$"
    )
    assert result["ok"] is True
    assert result["s4u"] == {"skipped": "rbcd_not_set"}


def test_trusts_enum_covers_outbound_filtered_forest_and_partnerless_trusts(
    monkeypatch: Any, tmp_path: Path
) -> None:
    outbound = _Entry(
        name="partner",
        trustPartner="partner.corp.test",
        trustDirection=2,
        trustType=2,
        trustAttributes=0,
        distinguishedName="CN=partner,CN=System,DC=corp,DC=test",
    )
    inbound_filtered = _Entry(
        name="forest",
        flatName="FOREST",
        trustPartner="forest.corp.test",
        trustDirection=1,
        trustType=2,
        trustAttributes=0x20 | 0x4,
        distinguishedName="CN=forest,CN=System,DC=corp,DC=test",
    )
    partnerless = _Entry(
        name="lonely",
        trustDirection=3,
        trustType=2,
        trustAttributes=0x8,
        distinguishedName="CN=lonely,CN=System,DC=corp,DC=test",
    )
    conn = _Conn([outbound, inbound_filtered, partnerless])
    monkeypatch.setattr(trusts_enum, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    graph = AttackGraph()

    result = trusts_enum.TrustsEnum().run(_target(), Session(tmp_path), graph)

    by_name = {t["name"]: t for t in result["trusts"]}
    outbound_paths = [p["id"] for p in by_name["partner"]["attack_paths"]]
    assert outbound_paths == ["outbound-resource-access"]
    assert by_name["partner"]["risk_notes"] == []
    forest_paths = [p["id"] for p in by_name["forest"]["attack_paths"]]
    assert forest_paths == []
    assert by_name["forest"]["sid_filtering"] is True
    assert by_name["forest"]["within_forest"] is True
    assert by_name["forest"]["risk_notes"] == []
    assert by_name["lonely"]["partner"] is None
    kinds = {edge.kind for edge in graph.edges}
    assert "ExternalTrust" not in kinds
    assert "SameForestTrust" in kinds
    edge_pairs = {(edge.source, edge.target) for edge in graph.edges}
    assert ("DOMAIN@FOREST.CORP.TEST", "DOMAIN@CORP.TEST") in edge_pairs


def _managed_blob(password: str) -> bytes:
    cur = password.encode("utf-16-le") + b"\x00\x00"
    header = struct.pack("<HHI", 1, 0, 16 + len(cur))
    header += struct.pack("<HHHH", 16, 0, 0, 0)
    return header + cur


class _GmsaLapsConn:
    def __init__(self, gmsa_entries: list[_Entry], laps_entries: list[_Entry]) -> None:
        self.gmsa_entries = gmsa_entries
        self.laps_entries = laps_entries
        self.entries: list[_Entry] = []
        self.unbound = False

    def search(self, base_dn: str, query: str, **kwargs: Any) -> None:
        self.entries = self.gmsa_entries if query == gmsa.GMSA_FILTER else self.laps_entries

    def unbind(self) -> None:
        self.unbound = True


def test_gmsa_laps_enum_filters_aces_and_handles_unparseable_managed_password(
    monkeypatch: Any, tmp_path: Path
) -> None:
    conn = _GmsaLapsConn(
        [
            _Entry(
                sAMAccountName="sqlsvc$",
                distinguishedName="CN=sqlsvc,DC=corp,DC=test",
                msDS_ManagedPasswordInterval=30,
                msDS_ManagedPassword=_managed_blob("Secret1!"),
            ),
            _Entry(
                sAMAccountName="oddsvc$",
                distinguishedName="CN=oddsvc,DC=corp,DC=test",
                msDS_ManagedPassword=12345,
            ),
        ],
        [
            _Entry(
                sAMAccountName="WEB01$",
                distinguishedName="CN=WEB01,DC=corp,DC=test",
                ms_Mcs_AdmPwd="legacy",
                msLAPS_Password="windows",
            ),
            _Entry(
                sAMAccountName="BARE$",
                distinguishedName="CN=BARE,DC=corp,DC=test",
            ),
        ],
    )
    monkeypatch.setattr(gmsa, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(gmsa, "fetch_sd", lambda connection, dn: b"descriptor")
    monkeypatch.setattr(
        gmsa,
        "parse_interesting_aces",
        lambda sd: [InterestingAce("S-1-5-21-100", "WriteDacl")],
    )
    graph = AttackGraph()

    result = gmsa.GmsaLapsEnum().run(_target(), Session(tmp_path), graph, include_secrets=True)

    assert result["gmsa_count"] == 2
    assert result["laps_computer_count"] == 2
    assert result["secrets_returned"] == 3
    odd = next(item for item in result["gmsas"] if item["sam"] == "oddsvc$")
    assert odd["managed_password_present"] is True
    assert "managed_password_parse" not in odd
    assert "managed_password_blob_len" not in odd
    bare = next(item for item in result["laps_computers"] if item["sam"] == "BARE$")
    assert bare["legacy_laps"] is False and bare["windows_laps"] is False
    assert all(edge.kind != "LAPSReadable" for edge in graph.edges if edge.target.endswith("BARE$"))


def test_gmsa_managed_password_present_but_secrets_not_requested(
    monkeypatch: Any, tmp_path: Path
) -> None:
    conn = _GmsaLapsConn(
        [
            _Entry(
                sAMAccountName="sqlsvc$",
                distinguishedName="CN=sqlsvc,DC=corp,DC=test",
                msDS_ManagedPassword=_managed_blob("Secret1!"),
            )
        ],
        [
            _Entry(
                sAMAccountName="WEB01$",
                distinguishedName="CN=WEB01,DC=corp,DC=test",
                ms_Mcs_AdmPwd="legacy",
            )
        ],
    )
    monkeypatch.setattr(gmsa, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(gmsa, "fetch_sd", lambda connection, dn: None)

    result = gmsa.GmsaLapsEnum().run(_target(), Session(tmp_path), AttackGraph())

    assert result["secrets_returned"] == 0
    item = result["gmsas"][0]
    assert item["managed_password_present"] is True
    assert "managed_password" not in item
    assert result["laps_computers"][0]["sam"] == "WEB01$"
