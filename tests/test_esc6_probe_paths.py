"""Deeper offline coverage for the ESC6 probe (certutil + RRP paths)."""

from __future__ import annotations

import subprocess
import sys
import types
from typing import Any

import adaf_attack.core.esc6_probe as esc6
from adaf_attack.core.esc6_probe import (
    _parse_editflags,
    probe_certutil,
    probe_esc6,
    probe_impacket_rrp,
)
from adaf_attack.core.target import Target


def test_parse_editflags_bare_hex_fallback() -> None:
    # First regex fails (no ':' '=' and no REG_DWORD), second regex matches.
    assert _parse_editflags("    EditFlags   0x40000  ") == 0x40000


def test_probe_certutil_parses_flags(monkeypatch: Any) -> None:
    monkeypatch.setattr(esc6.shutil, "which", lambda _n: "/usr/bin/certutil")

    def fake_run(args: list[str], **kwargs: Any) -> Any:
        assert "-config" in args and "CORP-CA" in args
        return types.SimpleNamespace(stdout="EditFlags REG_DWORD 0x00050000", stderr="")

    monkeypatch.setattr(esc6.subprocess, "run", fake_run)
    r = probe_certutil(ca_config="CORP-CA")
    assert r["ok"] is True
    assert r["esc6"] is True
    assert r["edit_flags_hex"] == "0x50000"


def test_probe_certutil_unparseable_output(monkeypatch: Any) -> None:
    monkeypatch.setattr(esc6.shutil, "which", lambda _n: "certutil")
    monkeypatch.setattr(
        esc6.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(stdout="nothing useful", stderr=""),
    )
    r = probe_certutil()
    assert r["available"] is True and r["ok"] is False
    assert "Could not parse" in r["note"]


def test_probe_certutil_subprocess_error(monkeypatch: Any) -> None:
    monkeypatch.setattr(esc6.shutil, "which", lambda _n: "certutil")

    def boom(*a: Any, **k: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd="certutil", timeout=20)

    monkeypatch.setattr(esc6.subprocess, "run", boom)
    r = probe_certutil()
    assert r["ok"] is False and "error" in r


def _install_fake_impacket(monkeypatch: Any, *, edit_flags: int = 0x40000) -> None:
    """Register minimal fake impacket modules used by probe_impacket_rrp."""

    class _SMBConnection:
        def __init__(self, *a: Any, **k: Any) -> None:
            pass

        def login(self, *a: Any, **k: Any) -> None:
            pass

        def getCredentials(self) -> tuple[str, str, str, str, str, str, None, None]:
            return ("a", "p", "corp.test", "", "", "", None, None)

    class _DCE:
        def connect(self) -> None:
            pass

        def bind(self, _uuid: Any) -> None:
            pass

        def disconnect(self) -> None:
            pass

    class _Transport:
        def set_smb_connection(self, _smb: Any) -> None:
            pass

        def get_dce_rpc(self) -> _DCE:
            return _DCE()

    rrp = types.ModuleType("impacket.dcerpc.v5.rrp")
    rrp.MSRPC_UUID_RRP = object()
    rrp.hOpenLocalMachine = lambda _dce: {"phKey": "root"}

    def _open_key(_dce: Any, _handle: Any, path: str) -> dict[str, Any]:
        return {"phkResult": path}

    rrp.hBaseRegOpenKey = _open_key

    def _enum_key(_dce: Any, _handle: Any, i: int) -> dict[str, str]:
        if i == 0:
            return {"lpNameOut": "CORP-CA"}
        raise RuntimeError("no more keys")

    rrp.hBaseRegEnumKey = _enum_key
    rrp.hBaseRegQueryValue = lambda _dce, _h, _name: (
        None,
        edit_flags.to_bytes(4, "little"),
    )

    transport = types.ModuleType("impacket.dcerpc.v5.transport")
    transport.DCERPCTransportFactory = lambda _binding: _Transport()

    smb_mod = types.ModuleType("impacket.smbconnection")
    smb_mod.SMBConnection = _SMBConnection

    v5 = types.ModuleType("impacket.dcerpc.v5")
    v5.rrp = rrp
    v5.transport = transport
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5", v5)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.rrp", rrp)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.transport", transport)
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", smb_mod)


def test_probe_impacket_rrp_reads_edit_flags(monkeypatch: Any) -> None:
    _install_fake_impacket(monkeypatch, edit_flags=0x40000)
    target = Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p")
    r = probe_impacket_rrp(target, ca_hostname="ca.corp.test")
    assert r["ok"] is True
    assert r["esc6"] is True
    assert r["cas"][0]["ca"] == "CORP-CA"


def test_probe_impacket_rrp_uses_hashes_and_no_esc6(monkeypatch: Any) -> None:
    _install_fake_impacket(monkeypatch, edit_flags=0x1)
    target = Target(
        domain="corp.test",
        dc_ip="10.0.0.1",
        username="a",
        hashes="aad3b435b51404eeaad3b435b51404ee:" + "0" * 32,
    )
    r = probe_impacket_rrp(target)
    assert r["ok"] is True
    assert r["esc6"] is False


def test_probe_impacket_rrp_missing_impacket(monkeypatch: Any) -> None:
    # Force the import to fail.
    for name in (
        "impacket.dcerpc.v5.rrp",
        "impacket.dcerpc.v5.transport",
        "impacket.smbconnection",
    ):
        monkeypatch.setitem(sys.modules, name, None)
    target = Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p")
    r = probe_impacket_rrp(target)
    assert r["available"] is False
    assert "Impacket not installed" in r["note"]


def test_probe_esc6_resolves_via_certutil(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        esc6,
        "probe_certutil",
        lambda ca_config=None: {"method": "certutil", "ok": True, "esc6": True},
    )
    target = Target(domain="corp.test", dc_ip="10.0.0.1")
    r = probe_esc6(target)
    assert r["resolved"] is True and r["esc6"] is True
    assert r["primary"]["method"] == "certutil"


def test_probe_esc6_resolves_via_rrp(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        esc6, "probe_certutil", lambda ca_config=None: {"method": "certutil", "ok": False}
    )
    monkeypatch.setattr(
        esc6,
        "probe_impacket_rrp",
        lambda target, ca_hostname=None: {"method": "impacket-rrp", "ok": True, "esc6": False},
    )
    target = Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p")
    r = probe_esc6(target, ca_hostnames=["ca.corp.test"])
    assert r["resolved"] is True
    assert r["primary"]["method"] == "impacket-rrp"
