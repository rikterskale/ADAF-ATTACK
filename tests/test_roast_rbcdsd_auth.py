"""Offline coverage for roast extraction, RBCD SD helpers, and auth branches."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import adaf_attack.core.auth as auth
import pytest
from adaf_attack.core.auth import describe_auth, get_kerberos_tgt, ldap3_bind_kwargs
from adaf_attack.core.rbcd_sd import (
    _sid_to_bytes,
    build_allowed_to_act_sd,
    sid_from_ldap_value,
)
from adaf_attack.core.roast_format import (
    _extract_cipher_and_etype,
    format_asrep_hashcat,
    format_tgs_hashcat,
)
from adaf_attack.core.target import Target

# --------------------------- roast_format ---------------------------


class _Node:
    """Minimal pyasn1-style component container."""

    def __init__(self, comps: dict[str, Any]) -> None:
        self._c = comps

    def getComponentByName(self, name: str) -> Any:
        return self._c.get(name)


def test_extract_from_pyasn1_style_ticket() -> None:
    cipher = bytes(range(32))
    ticket = _Node({"enc-part": _Node({"etype": 23, "cipher": cipher})})
    got_cipher, etype = _extract_cipher_and_etype(ticket)
    assert got_cipher == cipher
    assert etype == 23


def test_extract_hex_string_cipher() -> None:
    hex_cipher = bytes(range(32)).hex()
    ticket = SimpleNamespace(enc_part=SimpleNamespace(cipher=hex_cipher, etype=23))
    got, _ = _extract_cipher_and_etype(ticket)
    assert got == bytes(range(32))


def test_extract_non_hex_string_cipher() -> None:
    ticket = SimpleNamespace(enc_part=SimpleNamespace(cipher="nonhex-cipher-value!!", etype=23))
    got, _ = _extract_cipher_and_etype(ticket)
    assert got == b"nonhex-cipher-value!!"


def test_extract_memoryview_cipher() -> None:
    ticket = SimpleNamespace(
        enc_part=SimpleNamespace(cipher=memoryview(bytes(range(32))), etype=17)
    )
    got, etype = _extract_cipher_and_etype(ticket)
    assert got == bytes(range(32))
    assert etype == 17


def test_extract_returns_none_on_error() -> None:
    class _Bad:
        @property
        def enc_part(self) -> Any:
            raise RuntimeError("boom")

        def getComponentByName(self, name: str) -> Any:
            raise RuntimeError("boom")

    assert _extract_cipher_and_etype(_Bad()) == (None, None)


def test_format_tgs_none_when_no_cipher() -> None:
    assert format_tgs_hashcat("HTTP/x", "svc", "corp.test", SimpleNamespace()) is None


def test_format_tgs_exception_returns_none() -> None:
    ticket = SimpleNamespace(enc_part=SimpleNamespace(cipher=bytes(range(32)), etype=23))
    # username=None makes username.split(...) raise inside the try → None
    assert format_tgs_hashcat("HTTP/x", None, "corp.test", ticket) is None  # type: ignore[arg-type]


def test_format_asrep_short_and_exception() -> None:
    short = SimpleNamespace(enc_part=SimpleNamespace(cipher=b"short", etype=23))
    assert format_asrep_hashcat("svc", "corp.test", short) is None
    good = SimpleNamespace(enc_part=SimpleNamespace(cipher=bytes(range(32)), etype=23))
    assert format_asrep_hashcat(None, "corp.test", good) is None  # type: ignore[arg-type]


# --------------------------- rbcd_sd ---------------------------


def test_sid_to_bytes_invalid_raises() -> None:
    with pytest.raises(ValueError, match="Invalid SID"):
        _sid_to_bytes("not-a-sid")


def test_build_allowed_to_act_sd_roundtrips_sid() -> None:
    sd = build_allowed_to_act_sd("S-1-5-21-1-2-3-1105")
    assert isinstance(sd, bytes)
    assert len(sd) > 20


def test_sid_from_ldap_value_none() -> None:
    assert sid_from_ldap_value(None) is None


def test_sid_from_ldap_value_format_canonical() -> None:
    obj = SimpleNamespace(formatCanonical=lambda: "S-1-5-21-9-9-9")
    assert sid_from_ldap_value(obj) == "S-1-5-21-9-9-9"


def test_sid_from_ldap_value_bytes() -> None:
    from impacket.ldap.ldaptypes import LDAP_SID

    sid = LDAP_SID()
    sid.fromCanonical("S-1-5-21-1-2-3-1105")
    canonical = sid_from_ldap_value(sid.getData())
    assert canonical == "S-1-5-21-1-2-3-1105"


def test_sid_from_ldap_value_string_and_unparseable() -> None:
    assert sid_from_ldap_value("S-1-5-32-544") == "S-1-5-32-544"
    assert sid_from_ldap_value("just-text") is None


# --------------------------- auth ---------------------------


def test_describe_auth_aes_and_username_only() -> None:
    aes = Target(domain="c", dc_ip="1.1.1.1", username="a", aes_key="ff" * 16)
    assert describe_auth(aes) == "kerberos-aes-key"
    uname = Target(domain="c", dc_ip="1.1.1.1", username="a")
    assert "username only" in describe_auth(uname)
    anon = Target(domain="c", dc_ip="1.1.1.1")
    assert describe_auth(anon) == "anonymous"


def test_ldap3_bind_kwargs_hash_branch() -> None:
    t = Target(domain="corp.test", dc_ip="1.1.1.1", username="a", hashes="lm:nt")
    kw = ldap3_bind_kwargs(t)
    assert kw["authentication"] == "NTLM"
    assert kw["password"] == "nt"


def test_get_kerberos_tgt_requires_username() -> None:
    t = Target(domain="corp.test", dc_ip="1.1.1.1")
    with pytest.raises(RuntimeError, match="requires --username"):
        get_kerberos_tgt(t)


def test_get_kerberos_tgt_password_path(monkeypatch: Any) -> None:
    import impacket.krb5.kerberosv5 as kv5

    captured: dict[str, Any] = {}

    def fake_tgt(principal: Any, password: str, domain: str, *rest: Any) -> tuple[Any, ...]:
        captured["password"] = password
        captured["domain"] = domain
        return ("tgt", "cipher", "old", "session")

    monkeypatch.setattr(kv5, "getKerberosTGT", fake_tgt)
    t = Target(domain="corp.test", dc_ip="1.1.1.1", username="alice", password="pw")
    result = get_kerberos_tgt(t)
    assert result == ("tgt", "cipher", "old", "session")
    assert captured["password"] == "pw"
    assert captured["domain"] == "CORP.TEST"


def test_get_kerberos_tgt_ccache_path(monkeypatch: Any, tmp_path: Any) -> None:
    import impacket.krb5.kerberosv5 as kv5

    monkeypatch.setattr(kv5, "getKerberosTGT", lambda *a, **k: ("tgt", "c", "o", "s"))
    ccache = tmp_path / "krb5cc"
    ccache.write_text("x", encoding="utf-8")
    t = Target(
        domain="corp.test", dc_ip="1.1.1.1", username="alice", use_kerberos=True, ccache=str(ccache)
    )
    result = get_kerberos_tgt(t)
    assert result[0] == "tgt"
    assert auth.os.environ["KRB5CCNAME"] == str(ccache)
