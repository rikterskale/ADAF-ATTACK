"""Shared fakes for branch-closure gate tests (not collected by pytest)."""

from __future__ import annotations

from typing import Any

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class Attr:
    def __init__(self, value: Any = None) -> None:
        self.value = value
        self.values = value if isinstance(value, list) else ([] if value is None else [value])
        self.raw_values = self.values

    def __bool__(self) -> bool:
        return self.value is not None and self.value != []

    def __str__(self) -> str:
        return str(self.value)


class Entry:
    def __init__(self, **values: Any) -> None:
        self._values = {key: Attr(value) for key, value in values.items()}

    def __getattr__(self, name: str) -> Attr:
        if name in self._values:
            return self._values[name]
        alt = name.replace("_", "-")
        if alt in self._values:
            return self._values[alt]
        return Attr()

    def __getitem__(self, name: str) -> Attr:
        return self.__getattr__(name)


class Conn:
    def __init__(self, by_filter: dict[str, list[Entry]] | None = None) -> None:
        self.by_filter = by_filter or {}
        self.entries: list[Entry] = []
        self.result = {"result": 0, "description": "success"}
        self.modifies: list[Any] = []
        self.adds: list[Any] = []
        self.deletes: list[str] = []
        self.unbound = False

    def search(self, base: str, search_filter: str, **kwargs: Any) -> bool:
        for key, entries in self.by_filter.items():
            if key in search_filter or search_filter in key or key in base:
                self.entries = entries
                return True
        if base in self.by_filter:
            self.entries = self.by_filter[base]
            return True
        self.entries = []
        return True

    def modify(self, dn: str, changes: Any) -> bool:
        self.modifies.append((dn, changes))
        return True

    def add(self, dn: str, attributes: Any = None) -> bool:
        self.adds.append((dn, attributes))
        return True

    def delete(self, dn: str) -> bool:
        self.deletes.append(dn)
        return True

    def unbind(self) -> None:
        self.unbound = True


class FailModifyConn(Conn):
    """Connection whose modify() always fails, to exercise ok=False branches."""

    def modify(self, dn: str, changes: Any) -> bool:
        self.modifies.append((dn, changes))
        return False


def target(**kwargs: Any) -> Target:
    values = {
        "domain": "corp.test",
        "dc_ip": "10.0.0.1",
        "username": "alice",
        "password": "Secret1!",
        "ldaps": True,
    }
    values.update(kwargs)
    return Target(**values)


def sid_entry(sam: str, dn: str, sid: str = "S-1-5-21-1-2-3-1104") -> Entry:
    return Entry(
        sAMAccountName=sam,
        distinguishedName=dn,
        objectSid=sid,
        member=[],
        servicePrincipalName=[],
    )


def patch_ldap(monkeypatch: Any, module: Any, conn: Conn, base: str = "DC=corp,DC=test") -> None:
    monkeypatch.setattr(
        module, "ldap_connect", lambda t: (conn, base, "CN=Configuration,DC=corp,DC=test")
    )


def session(tmp_path: Any) -> Session:
    return Session(tmp_path)


def graph() -> AttackGraph:
    return AttackGraph()
