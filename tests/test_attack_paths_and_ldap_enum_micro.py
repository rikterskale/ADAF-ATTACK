"""Behavioral tests."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from adaf_attack.capabilities.attack_paths import AttackPaths
from adaf_attack.capabilities.ldap_enum import _list_attr as le_list_attr
from adaf_attack.capabilities.shadow_creds import _list_attr as sc_list_attr
from adaf_attack.core.bloodhound import import_bloodhound
from adaf_attack.core.creds import Credential, CredentialSet
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

# --------------------------- ldap_enum & shadow_creds _list_attr scalar ---------------------------


def test_ldap_enum_list_attr_scalar_raw() -> None:
    class _A:
        def __init__(self, v: Any) -> None:
            self.value = v

    class _E:
        k = _A("scalar")

    assert le_list_attr(_E(), "k") == ["scalar"]


def test_shadow_creds_list_attr_scalar_raw() -> None:
    class _A:
        def __init__(self, v: Any) -> None:
            self.value = v

    class _E:
        k = _A(42)

    assert sc_list_attr(_E(), "k") == [42]


# --------------------------- attack_paths → line 111 (long path truncation) ---------------------------


def test_attack_paths_long_path_truncation(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path / "sess")
    seed = AttackGraph()
    # Build a path of length > 8
    for i in range(10):
        seed.add_node(f"USER@N{i}@CORP", "User", sam=f"N{i}")
    for i in range(9):
        seed.add_edge(f"USER@N{i}@CORP", f"USER@N{i + 1}@CORP", "MemberOf")
    seed.add_node("GROUP@ADMINS@CORP", "Group", sam="Admins")
    seed.add_edge("USER@N9@CORP", "GROUP@ADMINS@CORP", "MemberOf")
    graph_file = tmp_path / "g.json"
    seed.save(graph_file)
    AttackPaths().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        session,
        AttackGraph(),
        graph_path=str(graph_file),
        start="N0",
        max_depth=15,
    )


# --------------------------- creds dump_redacted with aes_key ---------------------------


def test_creds_dump_redacted_aes_key() -> None:
    cs = CredentialSet(credentials=[Credential(username="a", aes_key="aa" * 16)])
    red = cs.dump_redacted()
    assert red[0]["aes_key"] == "***"


# --------------------------- bloodhound import empty node_id ---------------------------


def test_import_bloodhound_skips_empty_node_id(tmp_path: Path) -> None:
    p = tmp_path / "bh.json"
    p.write_text(
        json.dumps(
            {
                "graph": {
                    "nodes": [{"kinds": ["User"], "properties": {}}],  # no id/objectid/name
                    "edges": [],
                }
            }
        ),
        encoding="utf-8",
    )
    g = AttackGraph()
    counts = import_bloodhound(p, g)
    assert counts["nodes"] == 0


# --------------------------- paths.py line 30: is_kali comment skip ---------------------------


def test_is_kali_skips_comment_and_no_equals(tmp_path: Path) -> None:
    """is_kali handles comment lines and lines without '='."""
    release = tmp_path / "os-release"
    release.write_text("# comment line\nnoequalshere\nID=kali\nID_LIKE=debian\n", encoding="utf-8")
    from unittest.mock import patch

    import adaf_attack.core.paths as p

    with patch.object(p, "is_linux", return_value=True):
        assert p.is_kali(release)


# --------------------------- coercion_map skip host without sam ---------------------------


def test_coercion_map_skips_host_without_sam(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.capabilities.coercion_map as cm

    class _Conn:
        entries = [SimpleNamespace(sAMAccountName=None, dNSHostName=None)]
        unbound = False

        def search(self, *a: Any, **k: Any) -> None:
            pass

        def unbind(self) -> None:
            self.unbound = True

    monkeypatch.setattr(cm, "ldap_connect", lambda t: (_Conn(), "DC=corp,DC=test", None))
    result = cm.CoercionMap().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        Session(base_dir=tmp_path / "cm"),
        AttackGraph(),
    )
    assert result["hosts_checked"] == 0


# --------------------------- shadow_creds skip loops for entries without SAM ---------------------------


def test_shadow_creds_skips_entries_without_sam(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.capabilities.shadow_creds as sc

    class _Attr:
        def __init__(self, v: Any = None) -> None:
            self.value = v

        def __bool__(self) -> bool:
            return self.value is not None

    class _E:
        def __init__(self) -> None:
            self._v = {"sAMAccountName": _Attr(None)}

        def __getattr__(self, name: str) -> Any:
            return self._v.get(name, _Attr())

        def __getitem__(self, name: str) -> Any:
            return self.__getattr__(name)

    class _C:
        entries: list[_E] = [_E()]
        unbound = False

        def search(self, *a: Any, **k: Any) -> None:
            self.entries = [_E()]

        def unbind(self) -> None:
            self.unbound = True

    monkeypatch.setattr(sc, "ldap_connect", lambda t: (_C(), "DC=corp,DC=test", None))
    monkeypatch.setattr(sc, "fetch_sd", lambda c, dn: None)
    result = sc.ShadowCreds().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        Session(base_dir=tmp_path / "sh"),
        AttackGraph(),
    )
    assert result["accounts_with_keycred"] == []


# --------------------------- ticket_lifecycle import-pfx artifact missing ---------------------------


def test_ticket_lifecycle_pfx_to_pem_missing_file(tmp_path: Path) -> None:
    from adaf_attack.capabilities.ticket_lifecycle import TicketLifecycle

    session = Session(base_dir=tmp_path / "t")
    with pytest.raises(RuntimeError, match="existing PFX"):
        TicketLifecycle().run(
            Target(domain="c", dc_ip="1.1.1.1"),
            session,
            AttackGraph(),
            operation="pfx-to-pem",
            artifact=str(tmp_path / "no.pfx"),
        )


# --------------------------- trusts_enum forest trust risk note ---------------------------


def test_trusts_enum_forest_risk_note(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.capabilities.trusts_enum as te

    class _Attr:
        def __init__(self, v: Any = None) -> None:
            self.value = v

        def __bool__(self) -> bool:
            return self.value is not None

        def __str__(self) -> str:
            return str(self.value)

        def __int__(self) -> int:
            return int(self.value) if self.value is not None else 0

    class _E:
        def __init__(self, **v: Any) -> None:
            self._v = {k: _Attr(val) for k, val in v.items()}

        def __getattr__(self, name: str) -> _Attr:
            return self._v.get(name, _Attr())

        def __getitem__(self, name: str) -> _Attr:
            return self.__getattr__(name)

    class _C:
        entries: list[Any] = []
        unbound = False

        def search(self, *a: Any, **k: Any) -> None:
            # trustAttributes bit 0x8 → forest trust
            self.entries = [
                _E(
                    name="child",
                    trustPartner="child.corp.test",
                    trustDirection=3,  # 3 = bidirectional (has inbound)
                    trustType=2,
                    trustAttributes=0x8,  # forest transitive
                )
            ]

        def unbind(self) -> None:
            self.unbound = True

    monkeypatch.setattr(te, "ldap_connect", lambda t: (_C(), "DC=corp,DC=test", None))
    result = te.TrustsEnum().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        Session(base_dir=tmp_path / "trusts"),
        AttackGraph(),
    )
    assert result


# --------------------------- kerberoast redacted-console branch ---------------------------


def test_kerberoast_redacted_console_hint(monkeypatch: Any, tmp_path: Path) -> None:
    import adaf_attack.capabilities.kerberoast as kb

    class _Attr:
        def __init__(self, v: Any = None) -> None:
            self.value = v

        def __bool__(self) -> bool:
            return self.value is not None

        def __str__(self) -> str:
            return str(self.value)

        def __iter__(self) -> Any:
            return iter(self.value if isinstance(self.value, list) else [])

    class _E:
        def __init__(self) -> None:
            self._v = {
                "sAMAccountName": _Attr("svc"),
                "servicePrincipalName": _Attr(["HTTP/a"]),
                "userAccountControl": _Attr(0),
            }

        def __getattr__(self, name: str) -> Any:
            return self._v.get(name, _Attr())

        def __getitem__(self, name: str) -> Any:
            return self.__getattr__(name)

    class _C:
        entries: list[Any] = [_E()]
        unbound = False

        def search(self, *a: Any, **k: Any) -> None:
            pass

        def unbind(self) -> None:
            self.unbound = True

    monkeypatch.setattr(kb, "ldap_connect", lambda t: (_C(), "DC=corp,DC=test", None))
    monkeypatch.setattr(kb, "get_kerberos_tgt", lambda t: ("tgt", "cipher", None, "sk"))
    import impacket.krb5.kerberosv5 as kv5

    monkeypatch.setattr(kv5, "getKerberosTGS", lambda *a, **k: ("tgs", "c", None, "sk"))
    monkeypatch.setattr(kb, "format_tgs_hashcat", lambda *a, **k: "$krb5tgs$23$*x$X*$aa$bb")
    # include_secrets=False → triggers "Hashes redacted" print
    kb.Kerberoast().run(
        Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p"),
        Session(base_dir=tmp_path / "krb"),
        AttackGraph(),
        include_secrets=False,
    )


# --------------------------- graph.find_node fragment: skip if not match ---------------------------


def test_graph_find_node_returns_none_for_pattern_miss() -> None:
    g = AttackGraph()
    g.add_node("USER@ALICE@CORP", "User", sam="alice")
    # Query that doesn't match any SAM, kind fragment, or node id
    assert g.find_node("NOTANYTHING") is None


# --------------------------- forest_campaign compose_forest_campaign extra branches ---------------------------


def test_forest_campaign_compose_missing_graph_file(tmp_path: Path) -> None:
    import adaf_attack.core.forest_campaign as fc

    session = tmp_path / "s"
    session.mkdir()
    (session / "session.json").write_text('{"session_id": "s"}', encoding="utf-8")
    # No graph.json / trusts-enum.json → still returns something
    result = fc.compose_forest_campaign([session])
    assert "domains" in result
