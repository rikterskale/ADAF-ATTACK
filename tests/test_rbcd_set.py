"""Coverage for the RBCD write path (_set_rbcd) with a mocked LDAP connection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import adaf_attack.capabilities.rbcd as rbcd
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Attr:
    def __init__(self, value: Any = None) -> None:
        self.value = value
        self.raw_values = (
            value if isinstance(value, list) else ([value] if value is not None else [])
        )

    def __bool__(self) -> bool:
        return self.value is not None and self.value != []

    def __str__(self) -> str:
        return str(self.value)


class _Entry:
    def __init__(self, **attributes: Any) -> None:
        self._attributes = {name: _Attr(value) for name, value in attributes.items()}

    def __getattr__(self, name: str) -> _Attr:
        return self._attributes.get(name, self._attributes.get(name.replace("-", "_"), _Attr()))

    def __getitem__(self, name: str) -> _Attr:
        return self.__getattr__(name)


class _Conn:
    def __init__(self, responses: dict[str, list[_Entry]], *, modify_ok: bool = True) -> None:
        self.responses = responses
        self.entries: list[_Entry] = []
        self.modify_ok = modify_ok
        self.result = "success"
        self.unbound = False
        self.modified: list[tuple[str, Any]] = []

    def search(self, base_dn: str, search_filter: str, **kwargs: Any) -> None:
        # LEVEL-scope re-read of the target uses filter "(objectClass=*)" keyed by base_dn.
        self.entries = self.responses.get(search_filter, self.responses.get(base_dn, []))

    def modify(self, dn: str, changes: Any) -> bool:
        self.modified.append((dn, changes))
        self.result = "success" if self.modify_ok else "insufficientAccessRights"
        return self.modify_ok

    def unbind(self) -> None:
        self.unbound = True


def _target() -> Target:
    return Target(domain="corp.test", dc_ip="192.0.2.10")


def _base_responses() -> dict[str, list[_Entry]]:
    on_entry = _Entry(
        distinguishedName="CN=APP01,DC=corp,DC=test",
        objectSid="S-1-5-21-1-2-3-1105",
        **{rbcd.ATTR: None},
    )
    from_entry = _Entry(
        distinguishedName="CN=WEB01,DC=corp,DC=test",
        objectSid="S-1-5-21-1-2-3-1106",
    )
    prev_entry = _Entry(**{rbcd.ATTR: [b"\x01\x02"]})
    return {
        f"(&(objectClass=computer)({rbcd.ATTR}=*))": [],
        "(objectClass=computer)": [],
        "(sAMAccountName=APP01$)": [on_entry],
        "(sAMAccountName=WEB01$)": [from_entry],
        "CN=APP01,DC=corp,DC=test": [prev_entry],
    }


def test_set_rbcd_writes_descriptor(monkeypatch: Any, tmp_path: Path) -> None:
    conn = _Conn(_base_responses())
    monkeypatch.setattr(rbcd, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    result = rbcd.Rbcd().run(
        _target(),
        Session(tmp_path),
        AttackGraph(),
        force=True,
        set_on="APP01$",
        set_from="WEB01$",
    )
    attempt = result["set_attempt"]
    assert attempt["ok"] is True
    assert attempt["ldap_written"] is True
    assert attempt["set_on_dn"] == "CN=APP01,DC=corp,DC=test"
    assert attempt["set_from_sid"] == "S-1-5-21-1-2-3-1106"
    assert attempt["sd_len"] > 16
    assert attempt["previous"] == ["0102"]
    assert conn.modified
    # Cleanup registered on success
    session_dir = Path(result_session_path(result, tmp_path))
    assert session_dir.exists()


def result_session_path(result: dict[str, Any], tmp_path: Path) -> str:
    # rbcd.json is written under the session root
    matches = list(tmp_path.rglob("rbcd.json"))
    assert matches, "rbcd.json should be written"
    data = json.loads(matches[0].read_text(encoding="utf-8"))
    assert data["set_attempt"]["ok"] is True
    return str(matches[0].parent)


def test_set_rbcd_modify_failure(monkeypatch: Any, tmp_path: Path) -> None:
    conn = _Conn(_base_responses(), modify_ok=False)
    monkeypatch.setattr(rbcd, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    result = rbcd.Rbcd().run(
        _target(),
        Session(tmp_path),
        AttackGraph(),
        force=True,
        set_on="APP01$",
        set_from="WEB01$",
    )
    attempt = result["set_attempt"]
    assert attempt["ok"] is False
    assert attempt["ldap_written"] is False


def test_set_rbcd_lookup_failure(monkeypatch: Any, tmp_path: Path) -> None:
    responses = _base_responses()
    responses["(sAMAccountName=WEB01$)"] = []  # controlled source not found
    responses["(sAMAccountName=WEB01)"] = []
    conn = _Conn(responses)
    monkeypatch.setattr(rbcd, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    result = rbcd.Rbcd().run(
        _target(),
        Session(tmp_path),
        AttackGraph(),
        force=True,
        set_on="APP01$",
        set_from="WEB01$",
    )
    attempt = result["set_attempt"]
    assert attempt["ok"] is False
    assert "lookup failed" in attempt["error"]
