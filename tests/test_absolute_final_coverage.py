"""Absolute final push for 99% coverage."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import adaf_attack.capabilities.campaign_analysis as camp_an
import adaf_attack.capabilities.computer_takeover as ct
import pytest
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

# --------------------------- target.py: auth_user with domain, no-domain-in-username ---------------------------


def test_target_auth_user_variants() -> None:
    # domain prefix branch
    t = Target(domain="corp.test", dc_ip="1.1.1.1", username="alice")
    assert t.auth_user == "corp.test\\alice"
    # already has "\" → return as-is
    t2 = Target(domain="corp.test", dc_ip="1.1.1.1", username="OTHER\\bob")
    assert t2.auth_user == "OTHER\\bob"
    # already has "@"
    t3 = Target(domain="corp.test", dc_ip="1.1.1.1", username="alice@other.test")
    assert t3.auth_user == "alice@other.test"


def test_target_resolved_ccache_expanduser(tmp_path: Path) -> None:
    t = Target(domain="c", dc_ip="1.1.1.1", ccache=str(tmp_path / "cc"))
    result = t.resolved_ccache()
    assert result is not None
    assert str(tmp_path / "cc") in result


# --------------------------- campaign_analysis ---------------------------


def test_blast_radius_from_saved_graph(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path / "s")
    seed = AttackGraph()
    seed.add_node("USER@ALICE@CORP", "User", sam="alice")
    seed.add_node("GROUP@DOMAIN ADMINS@CORP", "Group", sam="Domain Admins", admin_count=True)
    seed.add_edge("USER@ALICE@CORP", "GROUP@DOMAIN ADMINS@CORP", "MemberOf")
    seed.save(session.path("graph.json"))
    result = camp_an.BlastRadius().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        session,
        AttackGraph(),
        start="alice",
    )
    assert result["high_value_impacts"]


def test_blast_radius_no_graph(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path / "s2")
    with pytest.raises(RuntimeError, match="No graph available"):
        camp_an.BlastRadius().run(
            Target(domain="c", dc_ip="1.1.1.1"), session, AttackGraph(), start="alice"
        )


def test_blast_radius_requires_start(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path / "s3")
    graph = AttackGraph()
    graph.add_node("USER@A@C", "User", sam="a")
    with pytest.raises(RuntimeError, match="requires --start"):
        camp_an.BlastRadius().run(Target(domain="c", dc_ip="1.1.1.1"), session, graph)


def test_blast_radius_start_not_found(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path / "s4")
    graph = AttackGraph()
    graph.add_node("USER@A@C", "User", sam="a")
    with pytest.raises(RuntimeError, match="Principal not found"):
        camp_an.BlastRadius().run(
            Target(domain="c", dc_ip="1.1.1.1"), session, graph, start="ghost"
        )


def test_purple_feedback_reads_events(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path / "s5")
    session.path("events.jsonl").write_text(
        json.dumps({"type": "kerberoast.complete", "ts": "now"})
        + "\n"
        + json.dumps({"type": "unknown.event", "ts": "now"})
        + "\n"
        + "not-valid-json\n",
        encoding="utf-8",
    )
    result = camp_an.PurpleFeedback().run(
        Target(domain="c", dc_ip="1.1.1.1"), session, AttackGraph()
    )
    assert result["count"] >= 1


# --------------------------- computer_takeover ---------------------------


class _Attr:
    def __init__(self, v: Any = None) -> None:
        self.value = v

    def __bool__(self) -> bool:
        return self.value is not None

    def __str__(self) -> str:
        return str(self.value)


class _E:
    def __init__(self, **v: Any) -> None:
        self._v = {k: _Attr(val) for k, val in v.items()}

    def __getattr__(self, name: str) -> _Attr:
        return self._v.get(name, _Attr())

    def __getitem__(self, name: str) -> _Attr:
        return self.__getattr__(name)


def test_computer_takeover_write_flow(monkeypatch: Any, tmp_path: Path) -> None:
    from adaf_attack.core.acl import InterestingAce

    computer = _E(
        sAMAccountName="DC01$",
        distinguishedName="CN=DC01,DC=corp,DC=test",
        servicePrincipalName=["HTTP/dc01"],
    )

    class _C:
        entries: list[_E] = [computer]
        result = "success"
        unbound = False

        def search(self, base_dn: str, filt: str, **kwargs: Any) -> None:
            self.entries = [computer]

        def modify(self, dn: str, changes: Any) -> bool:
            return True

        def unbind(self) -> None:
            self.unbound = True

    monkeypatch.setattr(ct, "ldap_connect", lambda t: (_C(), "DC=corp,DC=test", None))
    monkeypatch.setattr(ct, "fetch_sd", lambda c, dn: b"sd")
    monkeypatch.setattr(
        ct,
        "parse_interesting_aces",
        lambda sd: [InterestingAce("S-1-5-21-1", "WriteProperty")],
    )
    result = ct.ComputerTakeover().run(
        Target(domain="corp.test", dc_ip="10.0.0.1"),
        Session(base_dir=tmp_path / "ct"),
        AttackGraph(),
        force=True,
        write_target="DC01$",
        attribute="servicePrincipalName",
        value="HTTP/new",
    )
    assert result["change"]["ok"] is True


def test_computer_takeover_change_needs_force(monkeypatch: Any, tmp_path: Path) -> None:
    class _C:
        entries: list[Any] = []
        unbound = False

        def search(self, *a: Any, **k: Any) -> None:
            pass

        def unbind(self) -> None:
            self.unbound = True

    monkeypatch.setattr(ct, "ldap_connect", lambda t: (_C(), "DC=corp,DC=test", None))
    monkeypatch.setattr(ct, "fetch_sd", lambda c, dn: None)
    with pytest.raises(RuntimeError, match="requires --force"):
        ct.ComputerTakeover().run(
            Target(domain="corp.test", dc_ip="10.0.0.1"),
            Session(base_dir=tmp_path / "ctf"),
            AttackGraph(),
            attribute="servicePrincipalName",
        )


def test_computer_takeover_unsupported_attribute(monkeypatch: Any, tmp_path: Path) -> None:
    class _C:
        entries: list[Any] = []
        unbound = False

        def search(self, *a: Any, **k: Any) -> None:
            pass

        def unbind(self) -> None:
            self.unbound = True

    monkeypatch.setattr(ct, "ldap_connect", lambda t: (_C(), "DC=corp,DC=test", None))
    monkeypatch.setattr(ct, "fetch_sd", lambda c, dn: None)
    with pytest.raises(RuntimeError, match="not approved"):
        ct.ComputerTakeover().run(
            Target(domain="corp.test", dc_ip="10.0.0.1"),
            Session(base_dir=tmp_path / "ctu"),
            AttackGraph(),
            force=True,
            write_target="DC01$",
            attribute="sAMAccountName",  # not approved
            value="anything",
        )


# --------------------------- roast_format bytes cipher via getComponentByName ---------------------------


def test_roast_format_get_component_bytes() -> None:
    from adaf_attack.core.roast_format import _extract_cipher_and_etype

    class _Enc:
        def getComponentByName(self, name: str) -> Any:
            if name == "etype":
                return 23
            if name == "cipher":
                return bytes(range(32))
            return None

    class _Wrap:
        # No enc_part attribute - falls into pyasn1 pathway
        def getComponentByName(self, name: str) -> Any:
            if name == "enc-part":
                return _Enc()
            return None

    got, etype = _extract_cipher_and_etype(_Wrap())
    assert got is not None
    assert etype == 23
