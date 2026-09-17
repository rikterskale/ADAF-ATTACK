"""Regression tests for schema-sensitive discovery capabilities."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import adaf_attack.capabilities.gmsa_laps_enum as gmsa_laps
import adaf_attack.capabilities.identity_bridge as identity_bridge
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import schema_supported_attributes
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Attr:
    def __init__(self, value: Any = None) -> None:
        self.value = value

    def __bool__(self) -> bool:
        return self.value is not None

    def __str__(self) -> str:
        return str(self.value)


def _schema_conn(attribute_types: dict[str, Any]) -> SimpleNamespace:
    schema = SimpleNamespace(attribute_types=attribute_types)
    return SimpleNamespace(server=SimpleNamespace(schema=schema))


def test_schema_supported_attributes_returns_canonical_names_and_missing_items() -> None:
    conn = _schema_conn(
        {
            "mS-DS-ConsistencyGuid": SimpleNamespace(name=("mS-DS-ConsistencyGuid",)),
            "msLAPS-Password": SimpleNamespace(name="msLAPS-Password"),
        }
    )

    supported, unsupported = schema_supported_attributes(
        conn, ["MS-DS-CONSISTENCYGUID", "msLAPS-Password", "ms-Mcs-AdmPwd"]
    )

    assert supported == ["mS-DS-ConsistencyGuid", "msLAPS-Password"]
    assert unsupported == ["ms-Mcs-AdmPwd"]


def test_schema_supported_attributes_preserves_requests_without_schema_metadata() -> None:
    supported, unsupported = schema_supported_attributes(
        SimpleNamespace(), ["ms-Mcs-AdmPwd", "ms-Mcs-AdmPwd"]
    )

    assert supported == ["ms-Mcs-AdmPwd"]
    assert unsupported == []


class _LapsConnection:
    def __init__(self, attribute_types: dict[str, Any] | None = None) -> None:
        self.server = _schema_conn(
            attribute_types or {"msLAPS-Password": SimpleNamespace(name="msLAPS-Password")}
        ).server
        self.entries: list[Any] = []
        self.searches: list[tuple[str, list[str]]] = []

    def search(self, _base: str, ldap_filter: str, **kwargs: Any) -> None:
        self.searches.append((ldap_filter, list(kwargs["attributes"])))
        self.entries = []

    def unbind(self) -> None:
        return None


def test_gmsa_laps_filters_out_schema_extensions_that_are_not_installed(
    monkeypatch: Any, tmp_path: Path
) -> None:
    conn = _LapsConnection()
    monkeypatch.setattr(gmsa_laps, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))

    result = gmsa_laps.GmsaLapsEnum().run(
        Target(domain="corp.test", dc_ip="192.0.2.10"), Session(tmp_path), AttackGraph()
    )

    laps_filter, laps_attrs = conn.searches[1]
    assert laps_filter == "(&(objectCategory=computer)(|(msLAPS-Password=*)))"
    assert laps_attrs == ["sAMAccountName", "distinguishedName", "msLAPS-Password"]
    assert result["laps_schema"]["queried_attributes"] == ["msLAPS-Password"]
    assert "ms-Mcs-AdmPwd" in result["laps_schema"]["skipped_attributes"]


def test_gmsa_laps_skips_laps_search_when_no_laps_schema_is_installed(
    monkeypatch: Any, tmp_path: Path
) -> None:
    conn = _LapsConnection({"unrelatedAttribute": SimpleNamespace(name=None)})
    monkeypatch.setattr(gmsa_laps, "ldap_connect", lambda target: (conn, "DC=corp", None))

    result = gmsa_laps.GmsaLapsEnum().run(
        Target(domain="corp.test", dc_ip="192.0.2.10"), Session(tmp_path), AttackGraph()
    )

    assert len(conn.searches) == 1
    assert result["laps_computer_count"] == 0
    assert result["laps_schema"]["queried_attributes"] == []
    assert result["laps_schema"]["skipped_attributes"] == gmsa_laps.LAPS_SCHEMA_ATTRS


class _HybridConnection:
    def __init__(self) -> None:
        self.server = _schema_conn(
            {
                "mS-DS-ConsistencyGuid": SimpleNamespace(name=("mS-DS-ConsistencyGuid",)),
            }
        ).server
        entry = SimpleNamespace(
            sAMAccountName=_Attr("alice"),
            distinguishedName=_Attr("CN=Alice,DC=corp,DC=test"),
            description=_Attr(),
            servicePrincipalName=_Attr(),
            userPrincipalName=_Attr(),
            proxyAddresses=_Attr(),
        )
        setattr(entry, "mS-DS-ConsistencyGuid", _Attr(b"guid"))
        self.entries = [entry]
        self.attributes: list[str] = []

    def search(self, _base: str, _filter: str, **kwargs: Any) -> None:
        self.attributes = list(kwargs["attributes"])

    def unbind(self) -> None:
        return None


def test_hybrid_signals_uses_canonical_schema_name_and_reports_coverage(
    monkeypatch: Any, tmp_path: Path
) -> None:
    conn = _HybridConnection()
    monkeypatch.setattr(
        identity_bridge, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None)
    )

    result = identity_bridge.HybridSignals().run(
        Target(domain="corp.test", dc_ip="192.0.2.10"), Session(tmp_path), AttackGraph()
    )

    assert "mS-DS-ConsistencyGuid" in conn.attributes
    assert "msDS-ConsistencyGuid" not in conn.attributes
    assert result["posture"]["cloud_linked_principals"] == 1
    assert result["schema_coverage"]["queried_optional_attributes"] == ["mS-DS-ConsistencyGuid"]
    assert "msExchRecipientTypeDetails" in result["schema_coverage"]["skipped_optional_attributes"]
