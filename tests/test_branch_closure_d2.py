"""Branch-closure tests for bloodhound import and ESC6 RRP enumeration."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from typing import Any

from adaf_attack.core.bloodhound import import_bloodhound
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.target import Target


def test_import_bloodhound_skips_edges_without_endpoints(tmp_path: Path) -> None:
    path = tmp_path / "bh.json"
    path.write_text(
        json.dumps(
            {
                "graph": {
                    "nodes": [{"properties": {"objectid": "1"}, "label": "User"}],
                    "edges": [
                        {"source": "1", "target": "2", "label": "MemberOf"},
                        {"source": "", "target": "2"},
                        {"source": "1", "kind": "GenericAll"},
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    counts = import_bloodhound(path, AttackGraph())
    assert counts == {"nodes": 1, "edges": 1}


def _install_fake_impacket_all_enums(monkeypatch: Any) -> None:
    class _SMBConnection:
        def __init__(self, *a: Any, **k: Any) -> None:
            pass

        def login(self, *a: Any, **k: Any) -> None:
            pass

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
    rrp.hBaseRegOpenKey = lambda _dce, _h, path: {"phkResult": path}
    rrp.hBaseRegEnumKey = lambda _dce, _h, i: {"lpNameOut": f"CA-{i}"}
    rrp.hBaseRegQueryValue = lambda _dce, _h, _n: (None, (0x40000).to_bytes(4, "little"))

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


def test_probe_impacket_rrp_enum_exhausts_window(monkeypatch: Any) -> None:
    from adaf_attack.core.esc6_probe import probe_impacket_rrp

    _install_fake_impacket_all_enums(monkeypatch)
    target = Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p")
    result = probe_impacket_rrp(target)
    assert result["ok"] is True
    names = [item["ca"] for item in result["cas"]]
    assert len(names) == 32
    assert all(item["esc6"] is True for item in result["cas"])
