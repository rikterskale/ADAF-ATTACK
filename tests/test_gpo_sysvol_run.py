"""Offline end-to-end test for SYSVOL GPO enumeration."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import adaf_attack.capabilities.gpo_sysvol as gpo_sysvol
from adaf_attack.core.acl import InterestingAce
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class _Connection:
    def __init__(self) -> None:
        self.entries: list[Any] = []
        self.unbound = False

    def search(self, base_dn: str, search_filter: str, **kwargs: Any) -> None:
        self.entries = [
            SimpleNamespace(
                cn="{GPO-1}",
                displayName="Baseline",
                gPCFileSysPath="\\\\corp.test\\SYSVOL\\corp.test\\Policies\\{GPO-1}",
                distinguishedName="CN={GPO-1},DC=corp,DC=test",
            )
        ]

    def unbind(self) -> None:
        self.unbound = True


def test_gpo_sysvol_records_ldap_writers_without_network_or_write_probe(
    monkeypatch: Any, tmp_path: Path
) -> None:
    conn = _Connection()
    monkeypatch.setattr(gpo_sysvol, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(gpo_sysvol, "fetch_sd", lambda connection, dn: b"descriptor")
    monkeypatch.setattr(
        gpo_sysvol,
        "parse_interesting_aces",
        lambda sd: [InterestingAce("S-1-5-21-100", "WriteDacl")],
    )
    session = Session(tmp_path)
    graph = AttackGraph()

    result = gpo_sysvol.GpoSysvol().run(
        Target(domain="corp.test", dc_ip="192.0.2.10"), session, graph
    )

    assert result["gpo_count"] == 1
    assert result["writable_sysvol_count"] == 0
    assert result["stage"] is None
    assert result["gpos"][0]["ldap_writers"] == [{"sid": "S-1-5-21-100", "right": "WriteDacl"}]
    assert conn.unbound is True
    assert {(edge.source, edge.kind) for edge in graph.edges} == {("SID@S-1-5-21-100", "WriteGPO")}
    assert json.loads(session.path("gpo-sysvol.json").read_text(encoding="utf-8")) == result


def test_gpo_sysvol_stages_payload_and_falls_back_to_marker_path(
    monkeypatch: Any, tmp_path: Path
) -> None:
    calls: list[tuple[str, Any]] = []

    class _Smb:
        def connectTree(self, share: str) -> int:
            calls.append(("tree", share))
            return 7

        def createFile(self, tid: int, path: str) -> int:
            calls.append(("create", path))
            if "ScheduledTasks" in path:
                raise OSError("missing directory")
            return 8

        def writeFile(self, tid: int, fid: int, data: bytes) -> None:
            calls.append(("write", data))

        def closeFile(self, tid: int, fid: int) -> None:
            calls.append(("close", fid))

        def disconnectTree(self, tid: int) -> None:
            calls.append(("disconnect", tid))

        def logoff(self) -> None:
            calls.append(("logoff", None))

    monkeypatch.setattr(gpo_sysvol, "_smb_connect", lambda target, host: _Smb())
    result = gpo_sysvol.GpoSysvol()._stage_task(
        Target(domain="corp.test", dc_ip="192.0.2.10"),
        [
            {
                "cn": "{GPO-1}",
                "display_name": "Baseline",
                "sysvol": "\\\\corp.test\\SYSVOL\\corp.test\\Policies\\{GPO-1}",
            }
        ],
        "baseline",
        "<Tasks/>",
        Session(tmp_path),
    )

    assert result == {
        "ok": True,
        "path": "corp.test/Policies/{GPO-1}/Machine/adaf_staged.xml",
        "gpo": "{GPO-1}",
    }
    assert calls[0] == ("tree", "SYSVOL")
    assert calls[-1] == ("logoff", None)


def test_sysvol_unc_parser_and_smb_auth_paths(monkeypatch: Any) -> None:
    from impacket import smbconnection

    logins: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    class _Smb:
        def __init__(self, host: str, remote_name: str, timeout: int) -> None:
            assert (host, remote_name, timeout) == ("192.0.2.10", "192.0.2.10", 5)

        def login(self, *args: Any, **kwargs: Any) -> None:
            logins.append((args, kwargs))

    monkeypatch.setattr(smbconnection, "SMBConnection", _Smb)

    assert gpo_sysvol._parse_sysvol_unc("not-a-unc") is None
    assert gpo_sysvol._parse_sysvol_unc("\\\\host\\share") is None
    assert gpo_sysvol._parse_sysvol_unc("\\\\host\\share\\folder\\file") is None
    assert gpo_sysvol._parse_sysvol_unc("\\\\corp.test\\SYSVOL\\corp.test\\Policies\\{GPO}") == (
        "corp.test",
        "corp.test/Policies/{GPO}",
    )
    gpo_sysvol._smb_connect(
        Target(domain="corp.test", dc_ip="192.0.2.10", username="alice", hashes="00:11"),
        "192.0.2.10",
    )
    gpo_sysvol._smb_connect(
        Target(domain="corp.test", dc_ip="192.0.2.10", username="alice", password="secret"),
        "192.0.2.10",
    )
    gpo_sysvol._smb_connect(Target(domain="corp.test", dc_ip="192.0.2.10"), "192.0.2.10")

    assert logins[0][1] == {"lmhash": "00", "nthash": "11"}
    assert logins[1][0] == ("alice", "secret", "corp.test")
    assert logins[2][0] == ("", "")


def test_stage_task_rejects_unknown_or_invalid_gpo_paths(tmp_path: Path) -> None:
    capability = gpo_sysvol.GpoSysvol()
    target = Target(domain="corp.test", dc_ip="192.0.2.10")
    assert capability._stage_task(target, [], "missing", "<Tasks/>", Session(tmp_path)) == {
        "ok": False,
        "error": "GPO not found: missing",
    }
    assert capability._stage_task(
        target,
        [{"cn": "{GPO}", "display_name": "Baseline", "sysvol": "bad-path"}],
        "baseline",
        "<Tasks/>",
        Session(tmp_path),
    ) == {"ok": False, "error": "bad SYSVOL UNC"}


def test_gpo_sysvol_registers_cleanup_for_successful_staged_payload(
    monkeypatch: Any, tmp_path: Path
) -> None:
    conn = _Connection()
    monkeypatch.setattr(gpo_sysvol, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(gpo_sysvol, "fetch_sd", lambda connection, dn: None)
    monkeypatch.setattr(
        gpo_sysvol.GpoSysvol,
        "_stage_task",
        lambda self, target, gpos, stage_gpo, payload, session: {
            "ok": True,
            "path": "corp.test/Policies/{GPO-1}/Machine/adaf_staged.xml",
            "gpo": "{GPO-1}",
        },
    )
    session = Session(tmp_path)

    result = gpo_sysvol.GpoSysvol().run(
        Target(domain="corp.test", dc_ip="192.0.2.10"),
        session,
        AttackGraph(),
        force=True,
        gpo="{GPO-1}",
        payload="<Tasks/>",
    )

    assert result["stage"]["ok"] is True
    assert json.loads(session.path("cleanup.json").read_text())[0]["kind"] == "gpo-sysvol"


def test_gpo_sysvol_reports_reachable_sysvol_with_mocked_smb(
    monkeypatch: Any, tmp_path: Path
) -> None:
    class _Smb:
        def connectTree(self, share: str) -> int:
            assert share == "SYSVOL"
            return 7

        def listPath(self, share: str, path: str) -> list[object]:
            assert share == "SYSVOL"
            assert path.endswith("/*")
            return []

        def disconnectTree(self, tid: int) -> None:
            assert tid == 7

        def logoff(self) -> None:
            pass

    conn = _Connection()
    monkeypatch.setattr(gpo_sysvol, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None))
    monkeypatch.setattr(gpo_sysvol, "fetch_sd", lambda connection, dn: None)
    monkeypatch.setattr(gpo_sysvol, "_smb_connect", lambda target, host: _Smb())

    result = gpo_sysvol.GpoSysvol().run(
        Target(domain="corp.test", dc_ip="192.0.2.10", username="alice", password="secret"),
        Session(tmp_path),
        AttackGraph(),
    )

    assert result["gpos"][0]["sysvol_reachable"] is True
    assert result["gpos"][0]["sysvol_writable"] is None
