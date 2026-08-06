"""ESC6 probe unit tests (offline)."""

from adaf_attack.core.esc6_probe import (
    EDITF_ATTRIBUTESUBJECTALTNAME2,
    _parse_editflags,
    probe_certutil,
    probe_esc6,
)
from adaf_attack.core.target import Target


def test_editflags_bit() -> None:
    assert EDITF_ATTRIBUTESUBJECTALTNAME2 == 0x40000
    assert bool(0x40000 & EDITF_ATTRIBUTESUBJECTALTNAME2)
    assert not bool(0x1 & EDITF_ATTRIBUTESUBJECTALTNAME2)


def test_parse_editflags_variants() -> None:
    assert _parse_editflags("EditFlags REG_DWORD 0x40000") == 0x40000
    assert _parse_editflags("EditFlags = 0x00040000") == 0x40000
    assert _parse_editflags("EditFlags: 262144") == 262144
    assert _parse_editflags("no flags here") is None


def test_probe_certutil_soft_fail_without_binary() -> None:
    r = probe_certutil()
    assert r["method"] == "certutil"
    assert "available" in r


def test_probe_esc6_no_creds_unresolved() -> None:
    t = Target(domain="corp.local", dc_ip="10.0.0.1")
    r = probe_esc6(t)
    assert r["resolved"] is False
    assert r["esc6"] is None
    assert r["attempts"]
