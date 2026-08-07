"""Coverage for coercion helpers plus remaining CLI branches."""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

import adaf_attack.capabilities.coercion_map as coercion_map
from adaf_attack.cli import app
from adaf_attack.core.target import Target

runner = CliRunner()


# --------------------------- _tcp_open ---------------------------


def test_tcp_open_success(monkeypatch: Any) -> None:
    class _FakeConn:
        def __enter__(self) -> Any:
            return self

        def __exit__(self, *a: Any) -> None:
            pass

    monkeypatch.setattr(coercion_map.socket, "create_connection", lambda *a, **k: _FakeConn())
    assert coercion_map._tcp_open("host", 445) is True


def test_tcp_open_failure(monkeypatch: Any) -> None:
    def boom(*a: Any, **k: Any) -> Any:
        raise OSError("connection refused")

    monkeypatch.setattr(coercion_map.socket, "create_connection", boom)
    assert coercion_map._tcp_open("host", 445) is False


# --------------------------- _smb_pipe_check ---------------------------


class _FakeSmb:
    """Fake SMB connection tracking login mode + pipe open calls."""

    def __init__(self, *, login_ok: bool = True, spooler: bool = True, efsrpc: bool = True) -> None:
        self.login_ok = login_ok
        self._spooler = spooler
        self._efsrpc = efsrpc
        self.calls: dict[str, Any] = {}

    def login(
        self, user: str, password: str, domain: str = "", lmhash: str = "", nthash: str = ""
    ) -> None:
        self.calls["login"] = {
            "user": user,
            "password": password,
            "domain": domain,
            "lm": lmhash,
            "nt": nthash,
        }
        if not self.login_ok:
            raise RuntimeError("login denied")

    def connectTree(self, share: str) -> int:  # noqa: N802 — impacket API
        return 7

    def openFile(self, tid: int, pipe: str) -> int:  # noqa: N802
        if pipe == "spoolss":
            if self._spooler:
                return 1
            raise RuntimeError("no spooler")
        if pipe == "efsrpc":
            if self._efsrpc:
                return 2
            raise RuntimeError("no efsrpc")
        raise RuntimeError("unknown pipe")

    def closeFile(self, tid: int, fid: int) -> None:  # noqa: N802
        pass

    def logoff(self) -> None:
        pass


def _install_fake_smb(monkeypatch: Any, smb: _FakeSmb, *, raise_ctor: bool = False) -> None:
    mod = types.ModuleType("impacket.smbconnection")

    def _ctor(*a: Any, **k: Any) -> Any:
        if raise_ctor:
            raise RuntimeError("smb ctor failed")
        return smb

    mod.SMBConnection = _ctor
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", mod)


def test_smb_pipe_check_password_and_hashes(monkeypatch: Any) -> None:
    smb = _FakeSmb(spooler=True, efsrpc=False)
    _install_fake_smb(monkeypatch, smb)
    target = Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p")
    out = coercion_map._smb_pipe_check("host.corp.test", target)
    assert out["method"] == "impacket-smb"
    assert out["spooler"] is True and out["efsrpc"] is False

    # hashes branch
    smb2 = _FakeSmb()
    _install_fake_smb(monkeypatch, smb2)
    hash_target = Target(
        domain="corp.test",
        dc_ip="10.0.0.1",
        username="a",
        hashes="aad3b435b51404eeaad3b435b51404ee:" + "0" * 32,
    )
    out2 = coercion_map._smb_pipe_check("host.corp.test", hash_target)
    assert out2["spooler"] is True
    assert smb2.calls["login"]["nt"] == "0" * 32


def test_smb_pipe_check_null_login(monkeypatch: Any) -> None:
    smb = _FakeSmb(spooler=False, efsrpc=True)
    _install_fake_smb(monkeypatch, smb)
    target = Target(domain="corp.test", dc_ip="10.0.0.1")  # anonymous
    out = coercion_map._smb_pipe_check("host.corp.test", target)
    assert out["method"] == "impacket-smb"
    assert out["spooler"] is False and out["efsrpc"] is True


def test_smb_pipe_check_null_login_fails(monkeypatch: Any) -> None:
    smb = _FakeSmb(login_ok=False)
    _install_fake_smb(monkeypatch, smb)
    target = Target(domain="corp.test", dc_ip="10.0.0.1")
    out = coercion_map._smb_pipe_check("host.corp.test", target)
    assert out["error"] == "SMB login failed"


def test_smb_pipe_check_ctor_failure(monkeypatch: Any) -> None:
    _install_fake_smb(monkeypatch, _FakeSmb(), raise_ctor=True)
    target = Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p")
    out = coercion_map._smb_pipe_check("host.corp.test", target)
    assert "smb ctor failed" in out["error"]


def test_smb_pipe_check_impacket_missing(monkeypatch: Any) -> None:
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", None)
    target = Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p")
    out = coercion_map._smb_pipe_check("host.corp.test", target)
    assert out["method"] == "tcp-only"


# --------------------------- coercion capability closed/no-creds branches ---------------------------


class _CoercionConn:
    def __init__(self, sam: str = "WEB01$", dns: str = "web01.corp.test") -> None:
        from types import SimpleNamespace

        self.entries = [SimpleNamespace(sAMAccountName=sam, dNSHostName=dns)]
        self.unbound = False

    def search(self, *args: Any, **kwargs: Any) -> None:
        pass

    def unbind(self) -> None:
        self.unbound = True


def test_coercion_map_tcp_closed_and_no_creds(monkeypatch: Any, tmp_path: Path) -> None:
    from adaf_attack.core.graph import AttackGraph
    from adaf_attack.core.session import Session

    conn = _CoercionConn()
    monkeypatch.setattr(coercion_map, "ldap_connect", lambda t: (conn, "DC=corp,DC=test", None))
    # Anonymous target + closed 445 → both branches
    monkeypatch.setattr(coercion_map, "_tcp_open", lambda host, port: False)
    result_closed = coercion_map.CoercionMap().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        Session(tmp_path / "a"),
        AttackGraph(),
    )
    assert result_closed["hosts"][0]["method"] == "tcp-445-closed"

    conn2 = _CoercionConn()
    monkeypatch.setattr(coercion_map, "ldap_connect", lambda t: (conn2, "DC=corp,DC=test", None))
    monkeypatch.setattr(coercion_map, "_tcp_open", lambda host, port: True)
    result_no_creds = coercion_map.CoercionMap().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        Session(tmp_path / "b"),
        AttackGraph(),
    )
    assert result_no_creds["hosts"][0]["method"] == "tcp-445-open-no-creds"


# --------------------------- CLI extras ---------------------------


def test_list_capabilities_empty(monkeypatch: Any) -> None:
    from adaf_attack.core.registry import capability_registry

    saved = dict(capability_registry._capabilities)
    capability_registry._capabilities.clear()
    try:
        result = runner.invoke(app, ["list-capabilities"])
        assert result.exit_code == 0
        assert "No capabilities registered" in result.output
    finally:
        capability_registry._capabilities.update(saved)


def test_run_capability_unavailable(monkeypatch: Any) -> None:
    import adaf_attack.cli as cli
    from adaf_attack.core.runner import RunError

    monkeypatch.setattr(
        cli,
        "execute_capability",
        lambda *a, **k: (_ for _ in ()).throw(
            RunError("Capability 'x' has no runner implemented yet.")
        ),
    )
    result = runner.invoke(app, ["run", "x", "--domain", "corp.test", "--dc-ip", "10.0.0.1"])
    assert result.exit_code == 1
    assert "CAPABILITY_UNAVAILABLE" in result.output


def test_rank_paths_no_results(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.cli as cli

    class _EmptyGraph:
        def summary(self) -> dict[str, int]:
            return {"nodes": 0, "edges": 0}

        def rank_from_principals(self, starts: Any, **k: Any) -> list[Any]:
            return []

        def rank_exploit_chains(self, starts: Any, **k: Any) -> list[Any]:
            return []

    graph = tmp_path / "g.json"
    graph.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cli.AttackGraph, "from_file", staticmethod(lambda p: _EmptyGraph()))
    result = runner.invoke(app, ["rank-paths", "--graph", str(graph)])
    assert result.exit_code == 0
    assert "No paths found" in result.output


def test_run_all_optional_flags(monkeypatch: Any, tmp_path: Path) -> None:
    """Exercise every optional-option branch in the ``run`` command."""
    import adaf_attack.cli as cli

    seen: dict[str, Any] = {}

    def fake_exec(capability: str, target: Any, **kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return {"session_path": str(tmp_path), "ok": True}

    monkeypatch.setattr(cli, "execute_capability", fake_exec)
    graph_file = tmp_path / "g.json"
    graph_file.write_text("{}", encoding="utf-8")

    inline_payload = "<inline/>"
    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "run",
            "cap",
            "--domain",
            "corp.test",
            "--dc-ip",
            "10.0.0.1",
            "--graph",
            str(graph_file),
            "--start",
            "alice",
            "--template",
            "T",
            "--ca",
            "CA1",
            "--alt-name",
            "a@corp",
            "--descriptor-hex",
            "deadbeef",
            "--set-on",
            "TARGET$",
            "--set-from",
            "SRC$",
            "--key",
            "k.pem",
            "--cert",
            "c.pem",
            "--pfx",
            "x.pfx",
            "--gpo",
            "GPO-1",
            "--payload",
            inline_payload,
            "--artifact",
            "a.json",
        ],
    )
    assert result.exit_code == 0, result.output
    for k in (
        "graph_path",
        "start",
        "template",
        "ca",
        "alt_name",
        "descriptor_hex",
        "set_on",
        "set_from",
        "key",
        "cert",
        "pfx",
        "gpo",
        "payload",
        "artifact",
    ):
        assert k in seen
    # inline payload path (not @ and not existing file)
    assert seen["payload"] == inline_payload
