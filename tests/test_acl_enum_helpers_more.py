"""Coverage for acl_enum helpers (_sid_index, _domain_targets, _high_value_targets)."""

from __future__ import annotations

from typing import Any

import adaf_attack.capabilities.acl_enum as acl_enum


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
        self._values = {
            key: _Attr(**value) if isinstance(value, dict) else _Attr(value)
            for key, value in values.items()
        }

    def __getattr__(self, name: str) -> _Attr:
        return self._values.get(name, _Attr())

    def __getitem__(self, name: str) -> _Attr:
        return self.__getattr__(name)


class _Conn:
    """Fake LDAP connection routing queries by filter fragment."""

    def __init__(self) -> None:
        self.entries: list[_Entry] = []
        self._map: dict[str, list[_Entry]] = {}

    def route(self, key: str, entries: list[_Entry]) -> None:
        self._map[key] = entries

    def search(self, base_dn: str, filt: str, **kwargs: Any) -> None:
        for key, entries in self._map.items():
            if key in filt:
                self.entries = entries
                return
        self.entries = []


def test_sid_index_handles_missing_sid_and_object_classes() -> None:
    conn = _Conn()
    no_sid = _Entry(sAMAccountName="skip")  # objectSid missing → skipped
    canonical = _Entry(
        sAMAccountName="alice",
        objectSid=type("S", (), {"formatCanonical": lambda self: "S-1-5-21-100"})(),
        objectClass={"values": ["top", "user"]},
        distinguishedName="CN=Alice,DC=corp,DC=test",
    )
    computer = _Entry(
        sAMAccountName="DC01$",
        objectSid=type("S", (), {"formatCanonical": lambda self: "S-1-5-21-101"})(),
        objectClass={"values": ["computer"]},
        distinguishedName="CN=DC01,DC=corp,DC=test",
    )
    group = _Entry(
        sAMAccountName="Admins",
        objectSid=type("S", (), {"formatCanonical": lambda self: "S-1-5-21-102"})(),
        objectClass={"values": ["group"]},
        distinguishedName="CN=Admins,DC=corp,DC=test",
    )
    string_sid = _Entry(
        sAMAccountName=None,  # falsy sam → falls back to sid string
        objectSid="S-1-5-21-999",
        objectClass={"values": ["user"]},
        distinguishedName="CN=Bob,DC=corp,DC=test",
    )
    conn.route("objectClass=user", [no_sid, canonical, computer, group, string_sid])
    result = acl_enum._sid_index(conn, "DC=corp,DC=test")
    assert result["S-1-5-21-100"]["kind"] == "User"
    assert result["S-1-5-21-101"]["kind"] == "Computer"
    assert result["S-1-5-21-102"]["kind"] == "Group"
    # sam falls back to sid string when sAMAccountName missing
    assert result["S-1-5-21-999"]["sam"] == "S-1-5-21-999"


def test_high_value_targets_covers_all_object_classes() -> None:
    conn = _Conn()
    conn.route(
        "adminCount=1",
        [
            _Entry(
                sAMAccountName="Domain Admins",
                distinguishedName="CN=Domain Admins,DC=corp,DC=test",
                objectClass={"values": ["group"]},
            ),
            _Entry(
                sAMAccountName="DC01$",
                distinguishedName="CN=DC01,DC=corp,DC=test",
                objectClass={"values": ["computer"]},
            ),
            _Entry(
                sAMAccountName="alice",
                distinguishedName="CN=Alice,DC=corp,DC=test",
                objectClass={"values": ["user"]},
            ),
            # duplicate DN → deduped
            _Entry(
                sAMAccountName="alice",
                distinguishedName="CN=Alice,DC=corp,DC=test",
                objectClass={"values": ["user"]},
            ),
            _Entry(sAMAccountName=None, distinguishedName="skip"),  # skipped
        ],
    )
    out = acl_enum._high_value_targets(conn, "DC=corp,DC=test", "corp.test")
    dns = [t[1] for t in out]
    # includes domain root + adminsdholder + collected
    assert "DC=corp,DC=test" in dns
    assert "CN=Domain Admins,DC=corp,DC=test" in dns
    assert any(t[2] == "Computer" for t in out)
    assert any(t[2] == "User" for t in out)
    # de-duped
    assert len(dns) == len(set(d.lower() for d in dns))


def test_domain_targets_respects_limit_and_dedupes() -> None:
    conn = _Conn()
    # High-value first, then domain crawl entries
    conn.route(
        "adminCount=1",
        [
            _Entry(
                sAMAccountName="Domain Admins",
                distinguishedName="CN=Domain Admins,DC=corp,DC=test",
                objectClass={"values": ["group"]},
            ),
        ],
    )
    # domain_targets does its own broader search using "|" filter — reuse same route
    conn.route(
        "|(objectClass=user)",
        [
            _Entry(
                sAMAccountName="alice",
                distinguishedName="CN=Alice,DC=corp,DC=test",
                objectClass={"values": ["user"]},
            ),
            _Entry(
                sAMAccountName="WEB01$",
                distinguishedName="CN=WEB01,DC=corp,DC=test",
                objectClass={"values": ["computer"]},
            ),
            _Entry(
                sAMAccountName="Group2",
                distinguishedName="CN=Group2,DC=corp,DC=test",
                objectClass={"values": ["group"]},
            ),
            _Entry(sAMAccountName=None, distinguishedName="skip"),
            # duplicate of Domain Admins → filtered
            _Entry(
                sAMAccountName="Domain Admins",
                distinguishedName="CN=Domain Admins,DC=corp,DC=test",
                objectClass={"values": ["group"]},
            ),
        ],
    )
    out = acl_enum._domain_targets(conn, "DC=corp,DC=test", "corp.test", limit=50)
    labels = {t[2] for t in out}
    assert {"Computer", "User", "Group"} <= labels
