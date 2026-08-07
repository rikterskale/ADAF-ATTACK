"""Offline unit tests for ACL enumeration's LDAP-entry adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from adaf_attack.capabilities.acl_enum import _domain_targets, _high_value_targets, _sid_index


@dataclass
class _Attr:
    value: Any = None
    values: list[Any] | None = None

    def __bool__(self) -> bool:
        return self.value is not None or bool(self.values)

    def __str__(self) -> str:
        return str(self.value)


@dataclass
class _Entry:
    sAMAccountName: _Attr
    distinguishedName: _Attr
    objectClass: _Attr
    objectSid: _Attr = field(default_factory=_Attr)


class _Connection:
    def __init__(self, responses: list[list[_Entry]]) -> None:
        self._responses = iter(responses)
        self.entries: list[_Entry] = []
        self.calls: list[dict[str, Any]] = []

    def search(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append(kwargs)
        self.entries = next(self._responses)


def _entry(name: str, dn: str, classes: list[str], sid: str | None = None) -> _Entry:
    return _Entry(
        sAMAccountName=_Attr(name),
        distinguishedName=_Attr(dn),
        objectClass=_Attr(values=classes),
        objectSid=_Attr(sid),
    )


def test_sid_index_maps_principal_types_and_ignores_missing_sids() -> None:
    conn = _Connection(
        [
            [
                _entry("alice", "CN=Alice,DC=corp,DC=test", ["user"], "S-1-5-21-1"),
                _entry("ops", "CN=Ops,DC=corp,DC=test", ["group"], "S-1-5-21-2"),
                _entry("dc01$", "CN=DC01,DC=corp,DC=test", ["computer"], "S-1-5-21-3"),
                _entry("no-sid", "CN=NoSid,DC=corp,DC=test", ["user"]),
            ]
        ]
    )

    assert _sid_index(conn, "DC=corp,DC=test") == {
        "S-1-5-21-1": {"sam": "alice", "kind": "User", "dn": "CN=Alice,DC=corp,DC=test"},
        "S-1-5-21-2": {"sam": "ops", "kind": "Group", "dn": "CN=Ops,DC=corp,DC=test"},
        "S-1-5-21-3": {"sam": "dc01$", "kind": "Computer", "dn": "CN=DC01,DC=corp,DC=test"},
    }


def test_high_value_targets_adds_domain_and_deduplicates_directory_entries() -> None:
    conn = _Connection(
        [
            [
                _entry("Domain Admins", "CN=Domain Admins,DC=corp,DC=test", ["group"]),
                _entry("duplicate", "CN=Domain Admins,DC=corp,DC=test", ["group"]),
                _entry("dc01$", "CN=DC01,DC=corp,DC=test", ["computer"]),
            ]
        ]
    )

    targets = _high_value_targets(conn, "DC=corp,DC=test", "corp.test")

    assert ("DOMAIN@CORP.TEST", "DC=corp,DC=test", "Domain") in targets
    assert (
        "ADMINSDHOLDER@CORP.TEST",
        "CN=AdminSDHolder,CN=System,DC=corp,DC=test",
        "AdminSDHolder",
    ) in targets
    assert ("GROUP@DOMAIN ADMINS@CORP.TEST", "CN=Domain Admins,DC=corp,DC=test", "Group") in targets
    assert ("COMPUTER@DC01$@CORP.TEST", "CN=DC01,DC=corp,DC=test", "Computer") in targets
    assert sum(target[1] == "CN=Domain Admins,DC=corp,DC=test" for target in targets) == 1


def test_domain_targets_extends_high_value_targets_without_duplicates_and_honors_limit() -> None:
    conn = _Connection(
        [
            [_entry("Domain Admins", "CN=Domain Admins,DC=corp,DC=test", ["group"])],
            [
                _entry("Domain Admins", "CN=Domain Admins,DC=corp,DC=test", ["group"]),
                _entry("alice", "CN=Alice,DC=corp,DC=test", ["user"]),
                _entry("dc01$", "CN=DC01,DC=corp,DC=test", ["computer"]),
            ],
        ]
    )

    targets = _domain_targets(conn, "DC=corp,DC=test", "corp.test", limit=5)

    assert ("USER@ALICE@CORP.TEST", "CN=Alice,DC=corp,DC=test", "User") in targets
    assert ("COMPUTER@DC01$@CORP.TEST", "CN=DC01,DC=corp,DC=test", "Computer") in targets
    assert len(targets) == 5
    assert conn.calls[-1]["size_limit"] == 5
