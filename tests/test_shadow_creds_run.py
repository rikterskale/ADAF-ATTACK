"""Offline end-to-end coverage for Shadow Credentials enumeration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import adaf_attack.capabilities.shadow_creds as shadow_creds
from adaf_attack.core.acl import InterestingAce
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Attr:
    def __init__(self, value: Any = None, values: list[Any] | None = None) -> None:
        self.value = value
        self.values = values if values is not None else ([] if value is None else [value])

    def __bool__(self) -> bool:
        return self.value is not None or bool(self.values)

    def __str__(self) -> str:
        return str(self.value)


class _Entry:
    def __init__(self, **values: Any) -> None:
        self._values = {key: _Attr(value) for key, value in values.items()}

    def __getattr__(self, name: str) -> _Attr:
        return self._values.get(name, self._values.get(name.replace("-", "_"), _Attr()))

    def __getitem__(self, name: str) -> _Attr:
        return self.__getattr__(name)


class _Connection:
    def __init__(self, configured: _Entry, writable: _Entry) -> None:
        self.configured = configured
        self.writable = writable
        self.entries: list[_Entry] = []
        self.unbound = False

    def search(self, base_dn: str, search_filter: str, **kwargs: Any) -> None:
        self.entries = (
            [self.configured] if "KeyCredentialLink=*" in search_filter else [self.writable]
        )

    def unbind(self) -> None:
        self.unbound = True


def test_shadow_creds_records_existing_links_writable_principals_and_force_guard(
    monkeypatch: Any, tmp_path: Path
) -> None:
    configured = _Entry(
        sAMAccountName="alice",
        distinguishedName="CN=Alice,DC=corp,DC=test",
        objectClass=None,
        msDS_KeyCredentialLink=[b"one", b"two"],
    )
    configured._values["objectClass"] = _Attr(values=["user"])
    writable = _Entry(sAMAccountName="krbtgt", distinguishedName="CN=krbtgt,DC=corp,DC=test")
    conn = _Connection(configured, writable)
    monkeypatch.setattr(
        shadow_creds, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None)
    )
    monkeypatch.setattr(shadow_creds, "fetch_sd", lambda connection, dn: b"descriptor")
    monkeypatch.setattr(
        shadow_creds,
        "parse_interesting_aces",
        lambda sd: [InterestingAce("S-1-5-21-100", "WriteProperty")],
    )
    session = Session(tmp_path)
    graph = AttackGraph()

    result = shadow_creds.ShadowCreds().run(
        Target(domain="corp.test", dc_ip="192.0.2.10"),
        session,
        graph,
        write_target="krbtgt",
    )

    assert result["accounts_with_keycred"][0]["keycred_count"] == 2
    assert result["writable_principals"][0]["right"] == "WriteProperty"
    assert result["write_attempt"] == {"sam": "krbtgt", "skipped": "force_required"}
    assert conn.unbound is True
    assert {edge.kind for edge in graph.edges} == {"HasKeyCredentialLink", "WriteKeyCredentialLink"}
    assert json.loads(session.path("shadow-creds.json").read_text(encoding="utf-8")) == result
