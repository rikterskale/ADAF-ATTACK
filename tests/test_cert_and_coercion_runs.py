"""Offline execution tests for certificate-request and coercion-map capabilities."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import adaf_attack.capabilities.adcs_esc as adcs_esc
import adaf_attack.capabilities.cert_request as cert_request
import adaf_attack.capabilities.coercion_map as coercion_map
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def test_cert_request_requires_force_before_attempting_enrollment(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="requires --force"):
        cert_request.CertRequest().run(
            Target(domain="corp.test", dc_ip="192.0.2.10", username="alice", password="secret"),
            Session(tmp_path),
            AttackGraph(),
            template="UserTemplate",
        )


def test_cert_request_writes_redacted_playbook_when_certipy_is_unavailable(
    monkeypatch: Any, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        cert_request.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError()),
    )
    session = Session(tmp_path)
    result = cert_request.CertRequest().run(
        Target(domain="corp.test", dc_ip="192.0.2.10", username="alice", password="secret"),
        session,
        AttackGraph(),
        force=True,
        template="UserTemplate",
        ca="CorpCA",
        alt_name="admin@corp.test",
    )

    assert result["method"] == "playbook-only"
    assert "secret" not in Path(result["playbook"]).read_text(encoding="utf-8")
    assert json.loads(session.path("cert-request.json").read_text(encoding="utf-8"))["ok"] is False


def test_cert_request_keeps_password_out_of_certipy_argv(monkeypatch: Any, tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    class _Completed:
        returncode = 1
        stdout = ""
        stderr = ""

    def fake_run(*args: Any, **kwargs: Any) -> _Completed:
        captured["argv"] = args[0]
        captured["input"] = kwargs.get("input")
        return _Completed()

    monkeypatch.setattr(cert_request.subprocess, "run", fake_run)
    session = Session(tmp_path)
    cert_request.CertRequest().run(
        Target(domain="corp.test", dc_ip="192.0.2.10", username="alice", password="secret"),
        session,
        AttackGraph(),
        force=True,
        template="UserTemplate",
    )

    assert "secret" not in captured["argv"]
    assert captured["input"] == "secret\n"


def test_adcs_esc_keeps_password_out_of_certipy_argv(monkeypatch: Any, tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    class _Completed:
        returncode = 1
        stdout = ""
        stderr = ""

    def fake_run(*args: Any, **kwargs: Any) -> _Completed:
        captured["argv"] = args[0]
        captured["input"] = kwargs.get("input")
        return _Completed()

    monkeypatch.setattr(adcs_esc.subprocess, "run", fake_run)
    session = Session(tmp_path)
    result = adcs_esc._run_certipy(
        ["python", "-m", "certipy", "req", "-u", "alice@corp.test"],
        session,
        password="secret",
    )

    assert result["ok"] is False
    assert "secret" not in captured["argv"]
    assert captured["input"] == "secret\n"


class _Connection:
    def __init__(self) -> None:
        self.entries: list[Any] = []
        self.unbound = False

    def search(self, *args: Any, **kwargs: Any) -> None:
        self.entries = [
            SimpleNamespace(sAMAccountName="WEB01$", dNSHostName="web01.corp.test"),
            SimpleNamespace(sAMAccountName="FILE01$", dNSHostName=None),
        ]

    def unbind(self) -> None:
        self.unbound = True


def test_coercion_map_records_mocked_detect_only_surfaces(monkeypatch: Any, tmp_path: Path) -> None:
    conn = _Connection()
    monkeypatch.setattr(
        coercion_map, "ldap_connect", lambda target: (conn, "DC=corp,DC=test", None)
    )
    monkeypatch.setattr(coercion_map, "_tcp_open", lambda host, port: True)
    monkeypatch.setattr(
        coercion_map,
        "_smb_pipe_check",
        lambda host, target: {"spooler": host.startswith("web"), "efsrpc": True, "method": "mock"},
    )
    session = Session(tmp_path)
    graph = AttackGraph()
    result = coercion_map.CoercionMap().run(
        Target(domain="corp.test", dc_ip="192.0.2.10", username="alice", password="secret"),
        session,
        graph,
    )

    assert result["hosts_checked"] == 2
    assert result["spooler_open"] == 1
    assert result["efsrpc_open"] == 2
    assert conn.unbound is True
    assert {edge.kind for edge in graph.edges} == {"SpoolerOpen", "EfsrpcOpen"}
    assert (
        json.loads(session.path("coercion-map.json").read_text(encoding="utf-8"))["hosts_checked"]
        == 2
    )
