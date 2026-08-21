"""Unit tests for LDAP helpers, ACE builders, DNS records, and timeroast codecs."""

from __future__ import annotations

from typing import Any

import pytest

from adaf_attack.capabilities.credential_ops import (
    build_timeroast_request,
    parse_timeroast_response,
)
from adaf_attack.capabilities.dns_ops import (
    build_a_record,
    build_cname_record,
    build_srv_record,
    encode_dns_name,
)
from adaf_attack.core.acl import (
    append_ace_to_sd,
    build_allowed_ace,
    guid_str_to_bytes,
    sd_set_owner,
    sid_string_to_bytes,
)
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_ops import (
    attr_strings,
    attr_value,
    attr_values,
    distinguished_name,
    encode_unicode_pwd,
    finish,
    lookup_sam,
    register_add_value_rollback,
    register_attr_rollback,
    require_force,
    require_param,
    sam_variants,
    try_ntlm_bind,
)
from adaf_attack.core.rbcd_sd import build_allowed_to_act_sd
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Attr:
    def __init__(
        self, value: Any = None, values: list[Any] | None = None, raw: list[Any] | None = None
    ) -> None:
        self.value = value
        self.values = values if values is not None else ([] if value is None else [value])
        self.raw_values = raw if raw is not None else self.values

    def __bool__(self) -> bool:
        return self.value is not None or bool(self.values)


class _Entry:
    def __init__(self, **values: Any) -> None:
        self._values = values
        for key, value in values.items():
            setattr(
                self, key.replace("-", "_"), _Attr(value) if not isinstance(value, _Attr) else value
            )

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        return _Attr()

    def __getitem__(self, name: str) -> Any:
        if name == "boom":
            raise RuntimeError("nope")
        raw = self._values.get(name)
        if raw is None:
            return _Attr()
        return raw if isinstance(raw, _Attr) else _Attr(raw)


class _Conn:
    def __init__(self, entries: list[_Entry] | None = None) -> None:
        self._entries = entries or []
        self.entries: list[_Entry] = []
        self.result = "ok"

    def search(self, *args: Any, **kwargs: Any) -> None:
        self.entries = list(self._entries)


def test_require_helpers() -> None:
    require_force("x", True)
    with pytest.raises(RuntimeError, match="--force"):
        require_force("x", False)
    assert require_param({"a": "1"}, "b", "a") == "1"
    with pytest.raises(RuntimeError, match="Missing"):
        require_param({}, "a")
    assert sam_variants("") == []
    assert sam_variants("PC$") == ["PC$", "PC"]
    assert sam_variants("PC") == ["PC", "PC$"]


def test_attr_and_dn_helpers() -> None:
    assert attr_value(None, "x") is None
    entry = _Entry(sAMAccountName="alice", distinguishedName="CN=Alice,DC=corp,DC=test")
    assert attr_value(entry, "sAMAccountName") == "alice"
    assert distinguished_name(entry) == "CN=Alice,DC=corp,DC=test"
    assert attr_strings(entry, "missing") == []
    listed = _Entry()
    listed.spns = _Attr(value=["a", "b"])
    assert attr_values(listed, "spns") == ["a", "b"]
    from_values = _Entry()
    val_attr = _Attr(value=None)
    val_attr.values = ["from-values"]
    from_values.blob = val_attr
    assert attr_values(from_values, "blob") == ["from-values"]
    raw_only = _Entry()
    blob_attr = _Attr(value=None)
    blob_attr.values = []
    blob_attr.raw_values = [b"x"]
    raw_only.blob = blob_attr
    assert attr_values(raw_only, "blob") == [b"x"]
    scalar = _Entry(cn="n")
    assert attr_values(scalar, "cn") == ["n"]
    assert distinguished_name(_Entry()) == ""
    empty = _Entry()
    empty.entry_dn = "CN=FromEntry"
    assert distinguished_name(empty) == "CN=FromEntry"
    assert attr_value(entry, "boom") is None
    assert encode_unicode_pwd("p") == b'"\x00p\x00"\x00'

    class _Hyphen:
        def __init__(self) -> None:
            self.msDS_ManagedPassword = type("A", (), {"value": "secret"})()

    assert attr_value(_Hyphen(), "msDS-ManagedPassword") == "secret"

    class _Item:
        def __getitem__(self, name: str) -> str:
            return "plain"

    assert attr_value(_Item(), "cn") == "plain"

    class _Boom:
        def __getitem__(self, name: str) -> str:
            raise RuntimeError("no")

    assert attr_value(_Boom(), "cn") is None
    assert attr_value(object(), "cn") is None


def test_lookup_sam_variants_and_miss() -> None:
    conn = _Conn([_Entry(sAMAccountName="PC$", distinguishedName="CN=PC,DC=corp,DC=test")])
    found = lookup_sam(conn, "DC=corp,DC=test", "PC")
    assert found is not None
    assert found[0] == "CN=PC,DC=corp,DC=test"
    miss = _Conn([])
    assert lookup_sam(miss, "DC=corp,DC=test", "none") is None


def test_try_ntlm_bind_failure() -> None:
    ok, note = try_ntlm_bind(Target(domain="corp.test", dc_ip="127.0.0.1"), "alice", "bad")
    assert ok is False
    assert note


def test_try_ntlm_bind_success(monkeypatch: Any) -> None:
    class _C:
        def unbind(self) -> None:
            return None

    monkeypatch.setattr("adaf_attack.core.ldap_ops.Connection", lambda *a, **k: _C())
    ok, note = try_ntlm_bind(Target(domain="corp.test", dc_ip="127.0.0.1"), "alice", "pw")
    assert ok is True
    assert note == "ok"


def test_finish_and_rollback_helpers(tmp_path: Any) -> None:
    session = Session(tmp_path)
    graph = AttackGraph()
    result = finish(session, graph, "demo", {"ok": True}, ok=True)
    assert result["ok"] is True
    assert session.path("demo.json").is_file()
    register_attr_rollback(
        session, target_dn="CN=A", attribute="x", previous=[b"\x00"], rollback="r"
    )
    register_add_value_rollback(
        session, target_dn="CN=A", attribute="x", values=[b"\x01"], rollback="r"
    )
    payload = session.path("cleanup.json").read_text(encoding="utf-8")
    assert "ldap-attribute" in payload
    assert "ldap-add-value" in payload


def test_ace_and_sd_builders() -> None:
    sid = "S-1-5-21-1-2-3-4"
    with pytest.raises(ValueError):
        sid_string_to_bytes("nope")
    with pytest.raises(ValueError):
        guid_str_to_bytes("bad")
    ace = build_allowed_ace(sid)
    obj = build_allowed_ace(sid, object_guid="1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
    assert ace[0] == 0x00
    assert obj[0] == 0x05
    built = append_ace_to_sd(None, ace)
    again = append_ace_to_sd(built, obj)
    assert len(again) > len(built)
    owned = sd_set_owner(None, sid)
    assert owned
    owned2 = sd_set_owner(build_allowed_to_act_sd(sid), sid)
    assert owned2
    short = append_ace_to_sd(b"\x00" * 8, ace)
    assert short
    no_dacl = bytearray(b"\x01\x00\x04\x80" + b"\x00" * 16)
    appended = append_ace_to_sd(bytes(no_dacl), ace)
    assert appended
    overflow = bytearray(build_allowed_to_act_sd(sid))
    overflow[16:20] = (len(overflow) + 5).to_bytes(4, "little")
    assert append_ace_to_sd(bytes(overflow), ace)
    huge = bytearray(build_allowed_to_act_sd(sid))
    huge[22:24] = (5000).to_bytes(2, "little")
    assert append_ace_to_sd(bytes(huge), ace)
    owner_only = sd_set_owner(bytes(bytearray(b"\x01\x00\x04\x80" + b"\x00" * 16)), sid)
    assert owner_only


def test_dns_and_timeroast_codecs() -> None:
    assert encode_dns_name("a.b")[:1] == b"\x01"
    rec = build_a_record("10.0.0.1")
    assert rec[2:4] == (1).to_bytes(2, "little")
    with pytest.raises(ValueError):
        build_a_record("1.2.3")
    assert build_cname_record("wpad.corp.test")
    assert build_srv_record("dc.corp.test", 389)
    req = build_timeroast_request(1104)
    assert len(req) == 48
    assert parse_timeroast_response(b"\x00" * 40, 1) is None
    line = parse_timeroast_response(b"\x00" * 68, 1104)
    assert line and line.startswith("$sntp-ms$")
