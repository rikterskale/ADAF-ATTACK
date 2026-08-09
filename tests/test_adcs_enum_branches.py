"""Deep branch coverage for adcs-enum orchestration."""

from __future__ import annotations

from pathlib import Path as _Path
from types import SimpleNamespace
from typing import Any

import adaf_attack.capabilities.adcs_enum as adcs_enum
import pytest
from adaf_attack.capabilities.adcs_enum import _list_attr
from adaf_attack.core.acl import InterestingAce
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Conn:
    def __init__(self, per_filter: dict[str, list[Any]]) -> None:
        self.per_filter = per_filter
        self.entries: list[Any] = []
        self.unbound = False

    def search(self, base_dn: str, search_filter: str, **kwargs: Any) -> None:
        self.entries = self.per_filter.get(search_filter, [])

    def unbind(self) -> None:
        self.unbound = True


def test_list_attr_edge_cases() -> None:
    class _A:
        def __init__(self, v: Any) -> None:
            self.value = v

    # No attr → []
    assert _list_attr(object(), "missing") == []
    # value is None → []
    e = SimpleNamespace(k=_A(None))
    assert _list_attr(e, "k") == []


def test_adcs_enum_missing_config_nc(monkeypatch: Any, tmp_path: _Path) -> None:
    conn = _Conn({})
    monkeypatch.setattr(adcs_enum, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))

    with pytest.raises(RuntimeError, match="configurationNamingContext"):
        adcs_enum.AdcsEnum().run(
            Target(domain="corp.test", dc_ip="10.0.0.1"),
            Session(base_dir=tmp_path / "s"),
            AttackGraph(),
        )
    assert conn.unbound is True


def test_adcs_enum_esc2_esc3_and_esc5(monkeypatch: Any, tmp_path: _Path) -> None:
    ca = SimpleNamespace(
        entry_dn="CN=CA,DC=corp,DC=test",
        cn="CorpCA",
        dNSHostName="ca.corp.test",
        cACertificateDN="CN=CA",
    )
    template = SimpleNamespace()
    conn = _Conn(
        {
            "(objectClass=pKIEnrollmentService)": [ca],
            "(objectClass=pKICertificateTemplate)": [template],
        }
    )
    monkeypatch.setattr(
        adcs_enum,
        "ldap_connect",
        lambda t: (conn, "DC=corp,DC=test", "CN=Configuration,DC=corp,DC=test"),
    )
    # ESC2 candidate only (not ESC1)
    monkeypatch.setattr(
        adcs_enum,
        "_analyze_template",
        lambda entry: {
            "cn": "SubCA",
            "dn": "CN=SubCA,CN=Certificate Templates,DC=corp,DC=test",
            "esc1_candidate": False,
            "esc2_candidate": True,
            "esc3_agent_template": True,
            "esc3_requires_ra": True,
            "no_security_extension": False,
            "client_auth_eku": False,
            "enrollee_supplies_subject": False,
            "esc_tags": ["ESC2", "ESC3"],
        },
    )
    monkeypatch.setattr(adcs_enum, "fetch_sd", lambda c, dn: b"sd")
    # ACL parsing: ESC5-eligible right for PKI containers
    monkeypatch.setattr(
        adcs_enum,
        "parse_interesting_aces",
        lambda sd: [InterestingAce("S-1-5-21-500", "WriteDacl")],
    )
    monkeypatch.setattr(
        adcs_enum,
        "probe_esc6",
        lambda t, ca_hostnames: {"resolved": True, "esc6": False},
    )
    monkeypatch.setattr(adcs_enum, "_list_attr", lambda e, n: [])
    monkeypatch.setattr(adcs_enum, "_int_attr", lambda e, n: 0)

    session = Session(base_dir=tmp_path / "sess")
    graph = AttackGraph()
    result = adcs_enum.AdcsEnum().run(Target(domain="corp.test", dc_ip="10.0.0.1"), session, graph)
    # esc2_candidates populated
    assert "SubCA" in result["esc2_candidates"]
    # esc3 tracked
    assert "SubCA" in result["esc3_agent_templates"]
    assert "SubCA" in result["esc3_ra_required_templates"]
    # ESC5 hits from PKI containers
    assert result["esc5_pki_acl"]
    # ESC6 resolved false → no ESC6 edge
    assert not any(edge.kind == "ESC6" for edge in graph.edges)


def test_adcs_enum_esc6_unresolved(monkeypatch: Any, tmp_path: _Path) -> None:
    ca = SimpleNamespace(
        entry_dn="CN=CA,DC=corp,DC=test",
        cn="CorpCA",
        dNSHostName=None,  # forces fallback to dc_ip
        cACertificateDN="CN=CA",
    )
    conn = _Conn(
        {
            "(objectClass=pKIEnrollmentService)": [ca],
            "(objectClass=pKICertificateTemplate)": [],
        }
    )
    monkeypatch.setattr(
        adcs_enum,
        "ldap_connect",
        lambda t: (conn, "DC=corp,DC=test", "CN=Configuration,DC=corp,DC=test"),
    )
    monkeypatch.setattr(adcs_enum, "fetch_sd", lambda c, dn: None)
    monkeypatch.setattr(adcs_enum, "_list_attr", lambda e, n: [])
    monkeypatch.setattr(adcs_enum, "_int_attr", lambda e, n: 0)
    monkeypatch.setattr(
        adcs_enum,
        "probe_esc6",
        lambda t, ca_hostnames: {"resolved": False, "note": "Some note about ESC6"},
    )
    session = Session(base_dir=tmp_path / "sess")
    result = adcs_enum.AdcsEnum().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"), session, AttackGraph()
    )
    assert result["esc6"]["resolved"] is False
