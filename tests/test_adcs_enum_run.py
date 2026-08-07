"""Offline end-to-end tests for AD CS enumeration orchestration."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import adaf_attack.capabilities.adcs_enum as adcs_enum
from adaf_attack.core.acl import InterestingAce
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Connection:
    def __init__(self, ca: Any, template: Any) -> None:
        self.ca = ca
        self.template = template
        self.entries: list[Any] = []
        self.unbound = False

    def search(self, base_dn: str, search_filter: str, **kwargs: Any) -> None:
        if search_filter == "(objectClass=pKIEnrollmentService)":
            self.entries = [self.ca]
        elif search_filter == "(objectClass=pKICertificateTemplate)":
            self.entries = [self.template]
        else:
            self.entries = []

    def unbind(self) -> None:
        self.unbound = True


def test_adcs_enum_records_esc_findings_graph_edges_and_artifacts(
    monkeypatch: Any, tmp_path: Path
) -> None:
    ca = SimpleNamespace(entry_dn="CN=CorpCA,DC=corp,DC=test")
    template = SimpleNamespace()
    conn = _Connection(ca, template)
    monkeypatch.setattr(
        adcs_enum,
        "ldap_connect",
        lambda target: (conn, "DC=corp,DC=test", "CN=Configuration,DC=corp,DC=test"),
    )
    monkeypatch.setattr(
        adcs_enum,
        "_analyze_template",
        lambda entry: {
            "cn": "UserTemplate",
            "dn": "CN=UserTemplate,CN=Certificate Templates,DC=corp,DC=test",
            "esc1_candidate": True,
            "esc2_candidate": False,
            "esc3_agent_template": False,
            "esc3_requires_ra": False,
            "no_security_extension": True,
            "client_auth_eku": True,
            "enrollee_supplies_subject": True,
            "esc_tags": ["ESC1"],
        },
    )
    monkeypatch.setattr(adcs_enum, "fetch_sd", lambda connection, dn: b"descriptor")
    monkeypatch.setattr(
        adcs_enum,
        "parse_interesting_aces",
        lambda sd: [
            InterestingAce("S-1-5-21-100", "ManageCA"),
            InterestingAce("S-1-5-21-200", "Enroll"),
            InterestingAce("S-1-5-21-300", "WriteDacl"),
        ],
    )
    monkeypatch.setattr(
        adcs_enum, "probe_esc6", lambda target, ca_hostnames: {"resolved": True, "esc6": True}
    )
    monkeypatch.setattr(
        adcs_enum,
        "_list_attr",
        lambda entry, name: {
            "certificateTemplates": ["UserTemplate"],
            "msPKI-Enrollment-Servers": ["https://ca.corp.test/certsrv"],
            "msPKI-RA-Policies": [],
        }.get(name, []),
    )
    monkeypatch.setattr(adcs_enum, "_int_attr", lambda entry, name: 0)
    ca.cn = "CorpCA"
    ca.dNSHostName = "ca.corp.test"
    ca.cACertificateDN = "CN=CorpCA"
    session = Session(tmp_path)
    graph = AttackGraph()

    result = adcs_enum.AdcsEnum().run(
        Target(domain="corp.test", dc_ip="192.0.2.10"), session, graph
    )

    assert result["esc1_candidates"] == ["UserTemplate"]
    assert result["esc7_ca_acl"] == [{"ca": "CorpCA", "sid": "S-1-5-21-100", "right": "ManageCA"}]
    assert result["esc8_web_enrollment"] == [
        {"ca": "CorpCA", "endpoint": "https://ca.corp.test/certsrv"}
    ]
    assert result["esc9_candidates"] == ["UserTemplate"]
    assert result["esc6"] == {"resolved": True, "esc6": True}
    assert conn.unbound is True
    assert {edge.kind for edge in graph.edges} >= {
        "ESC1",
        "ESC1Enrollable",
        "ESC4",
        "ESC6",
        "ESC7",
        "ESC8WebEnrollment",
        "ESC9",
    }
    assert json.loads(session.path("adcs-enum.json").read_text(encoding="utf-8")) == result
