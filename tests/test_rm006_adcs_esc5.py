"""Behavioral evidence for the implemented AD CS ESC5 enumeration path."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import adaf_attack.capabilities.adcs_enum as adcs_enum
from adaf_attack.core.acl import InterestingAce
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Connection:
    def __init__(self, responses: dict[str, list[Any]]) -> None:
        self.responses = responses
        self.entries: list[Any] = []
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.unbound = False

    def search(self, base_dn: str, search_filter: str, **kwargs: Any) -> bool:
        self.calls.append((base_dn, search_filter, kwargs))
        self.entries = self.responses.get(search_filter, [])
        return True

    def unbind(self) -> None:
        self.unbound = True


def test_scan_ca_server_acls_reports_write_rights_and_escapes_host_filters(
    monkeypatch: Any,
) -> None:
    dns = "ca(01).corp.test"
    escaped = str(adcs_enum.escape_filter_chars(dns))
    server_dn = "CN=CA01,OU=Servers,DC=corp,DC=test"
    connection = _Connection(
        {f"(&(objectClass=computer)(dNSHostName={escaped}))": [SimpleNamespace(entry_dn=server_dn)]}
    )
    monkeypatch.setattr(adcs_enum, "fetch_sd", lambda conn, dn: b"server-sd")
    monkeypatch.setattr(
        adcs_enum,
        "parse_interesting_aces",
        lambda sd: [
            InterestingAce("S-1-5-21-100", "WriteDacl"),
            InterestingAce("S-1-5-21-100", "WriteDacl"),
            InterestingAce("S-1-5-21-100", "ReadProperty"),
        ],
    )
    result: dict[str, Any] = {"esc5_ca_server_acl": []}
    graph = AttackGraph()

    adcs_enum._scan_ca_server_acls(
        connection,
        "DC=corp,DC=test",
        [{"cn": "CorpCA", "dns": dns}, {"cn": "NoHost", "dns": None}],
        graph,
        result,
    )

    assert len(connection.calls) == 1
    assert "dNSHostName=ca\\2801\\29.corp.test" in connection.calls[0][1]
    assert result["esc5_ca_server_acl"] == [
        {
            "ca": "CorpCA",
            "server": dns,
            "dn": server_dn,
            "sid": "S-1-5-21-100",
            "right": "WriteDacl",
        }
    ]
    assert any(
        edge.kind == "ESC5" and edge.target == "CA-SERVER@CA(01).CORP.TEST" for edge in graph.edges
    )


def test_adcs_enum_persists_ca_server_esc5_evidence_and_guidance(
    monkeypatch: Any, tmp_path: Any
) -> None:
    pki_base = "CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=test"
    ca = SimpleNamespace(
        entry_dn="CN=CorpCA,CN=Enrollment Services," + pki_base,
        cn="CorpCA",
        dNSHostName="ca.corp.test",
        cACertificateDN="CN=CorpCA",
    )
    server_dn = "CN=CA01,OU=Servers,DC=corp,DC=test"
    server = SimpleNamespace(
        entry_dn=server_dn,
        sAMAccountName="CA01$",
        dNSHostName="ca.corp.test",
    )

    class RunConnection(_Connection):
        def search(self, base_dn: str, search_filter: str, **kwargs: Any) -> bool:
            self.calls.append((base_dn, search_filter, kwargs))
            if search_filter == "(objectClass=pKIEnrollmentService)":
                self.entries = [ca]
            elif search_filter.startswith("(&(objectClass=computer)(dNSHostName="):
                self.entries = [server]
            else:
                self.entries = []
            return True

    connection = RunConnection({})
    fetched: list[str] = []
    monkeypatch.setattr(
        adcs_enum,
        "ldap_connect",
        lambda target: (connection, "DC=corp,DC=test", "CN=Configuration,DC=corp,DC=test"),
    )
    monkeypatch.setattr(adcs_enum, "_list_attr", lambda entry, name: [])
    monkeypatch.setattr(adcs_enum, "_int_attr", lambda entry, name: 0)

    def fetch(connection_arg: Any, dn: str) -> bytes | None:
        fetched.append(dn)
        return b"server-sd" if dn == server_dn else None

    monkeypatch.setattr(adcs_enum, "fetch_sd", fetch)
    monkeypatch.setattr(
        adcs_enum,
        "parse_interesting_aces",
        lambda sd: [InterestingAce("S-1-5-21-100", "GenericWrite")],
    )
    monkeypatch.setattr(adcs_enum, "probe_esc6", lambda target, ca_hostnames: {"resolved": False})

    session = Session(base_dir=tmp_path / "session")
    graph = AttackGraph()
    result = adcs_enum.AdcsEnum().run(Target(domain="corp.test", dc_ip="10.0.0.1"), session, graph)

    assert result["esc5_ca_server_acl"] == [
        {
            "ca": "CorpCA",
            "server": "ca.corp.test",
            "dn": server_dn,
            "sid": "S-1-5-21-100",
            "right": "GenericWrite",
        }
    ]
    assert "not in this pass" not in result["notes"]["ESC5"]
    assert f"CN=Certificate Templates,{pki_base}" in fetched
    assert f"CN=Enrollment Services,{pki_base}" in fetched
    assert any(edge.kind == "ESC5" for edge in graph.edges)
    assert connection.unbound
