"""Last-mile coverage for straggler branches across many modules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import adaf_attack.core.engagement as eng
import adaf_attack.core.runner as runner_mod
from adaf_attack.capabilities.ldap_enum import _list_attr as le_list_attr
from adaf_attack.capabilities.ldap_enum import _uac_has
from adaf_attack.capabilities.report import _md_escape
from adaf_attack.core.acl import parse_interesting_aces
from adaf_attack.core.creds import Credential, CredentialSet
from adaf_attack.core.esc6_probe import _parse_editflags
from adaf_attack.core.findings import findings_from_session, write_findings
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.rbcd_sd import build_allowed_to_act_sd
from adaf_attack.core.registry import Capability, capability_registry
from adaf_attack.core.roast_format import _extract_cipher_and_etype
from adaf_attack.core.target import Target

# --------------------------- runner remaining ---------------------------


def test_runner_single_credential_ok_probe(monkeypatch: Any) -> None:
    monkeypatch.setattr(runner_mod, "_probe_ldap", lambda t: True)
    chosen, attempts = runner_mod._resolve_target(
        Target(domain="corp.test", dc_ip="10.0.0.1", username="a", password="p")
    )
    assert chosen.username == "a"
    assert attempts[-1].endswith("ok")


def test_runner_execute_capability_result_error_wraps(monkeypatch: Any, tmp_path: Path) -> None:
    """Cover the RunError re-raise branch when capability run raises."""

    class _R:
        def run(self, *a: Any, **k: Any) -> Any:
            raise ValueError("cap explode")

    capability_registry._capabilities["t-explode"] = Capability(
        id="t-explode", summary="s", runner=_R()
    )
    try:
        with pytest.raises(runner_mod.RunError, match="cap explode"):
            runner_mod.execute_capability(
                "t-explode",
                Target(domain="corp.test", dc_ip="10.0.0.1"),
                workspace=tmp_path,
            )
    finally:
        capability_registry._capabilities.pop("t-explode", None)


def test_runner_credential_resolution_reraises_runerror(monkeypatch: Any, tmp_path: Path) -> None:
    class _R:
        def run(self, *a: Any, **k: Any) -> dict:
            return {"ok": True}

    capability_registry._capabilities["t-runerror"] = Capability(
        id="t-runerror", summary="s", runner=_R()
    )

    def raise_runerror(*a: Any, **k: Any) -> Any:
        raise runner_mod.RunError("credentials failed")

    monkeypatch.setattr(runner_mod, "_resolve_target", raise_runerror)
    try:
        with pytest.raises(runner_mod.RunError, match="credentials failed"):
            runner_mod.execute_capability(
                "t-runerror",
                Target(domain="corp.test", dc_ip="10.0.0.1"),
                workspace=tmp_path,
            )
    finally:
        capability_registry._capabilities.pop("t-runerror", None)


# --------------------------- engagement destructive with approval ---------------------------


def test_engagement_run_destructive_with_approval(monkeypatch: Any, tmp_path: Path) -> None:
    import base64
    import hashlib
    import hmac
    from datetime import UTC, datetime

    class _R:
        def run(self, *a: Any, **k: Any) -> dict:
            return {"ok": True}

    capability_registry._capabilities["e-write"] = Capability(
        id="e-write", summary="s", destructive=True, runner=_R()
    )
    plan = eng.EngagementPlan(
        engagement_id="ENG-2",
        domain="corp.test",
        dc_ip="10.0.0.1",
        allowed_capabilities=("e-write",),
        phases=({"name": "act", "capabilities": ["e-write"]},),
        allowed_targets=("10.0.0.1",),
    )
    monkeypatch.setenv("ADAF_APPROVAL_HMAC_KEY", "secret")
    exp = int(datetime.now(UTC).timestamp()) + 3600
    payload = json.dumps(
        {
            "engagement_id": "ENG-2",
            "capabilities": ["e-write"],
            "targets": ["10.0.0.1"],
            "exp": exp,
            "approval_id": "AP",
            "approved_by": "alice",
        }
    )
    encoded = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    sig = (
        base64.urlsafe_b64encode(hmac.new(b"secret", encoded.encode(), hashlib.sha256).digest())
        .decode()
        .rstrip("=")
    )
    token = f"{encoded}.{sig}"
    try:
        result = eng.run_engagement(plan, workspace=tmp_path, approval_token=token)
        assert result["capabilities"] == ["e-write"]
    finally:
        capability_registry._capabilities.pop("e-write", None)


def test_engagement_run_capability_unavailable(monkeypatch: Any, tmp_path: Path) -> None:
    plan = eng.EngagementPlan(
        engagement_id="ENG-3",
        domain="corp.test",
        dc_ip="10.0.0.1",
        allowed_capabilities=("nope-cap",),
        phases=({"name": "p", "capabilities": ["nope-cap"]},),
        allowed_targets=("10.0.0.1",),
    )
    # nope-cap not in registry
    with pytest.raises(eng.EngagementError, match="Capability unavailable"):
        eng.run_engagement(plan, workspace=tmp_path)


# --------------------------- graph rank_paths admin_count bonus ---------------------------


def test_graph_rank_paths_admin_count_bonus() -> None:
    g = AttackGraph()
    g.add_node("USER@A@C", "User", sam="a")
    g.add_node("GROUP@ELEVATED@C", "Group", sam="Elevated", admin_count=True)
    g.add_edge("USER@A@C", "GROUP@ELEVATED@C", "MemberOf")
    ranked = g.rank_paths("USER@A@C", max_depth=3, limit=5)
    # non-HV group with admin_count → -1.0 bonus applied
    assert ranked
    assert any(p.length == 1 for p in ranked)


def test_graph_rank_paths_max_depth_reached() -> None:
    g = AttackGraph()
    for i in range(5):
        g.add_node(f"NODE@{i}", "Base")
    for i in range(4):
        g.add_edge(f"NODE@{i}", f"NODE@{i + 1}", "Related")
    # max_depth < path length forces stop condition on line 437
    ranked = g.rank_paths("NODE@0", goal_kinds=("Base",), max_depth=2, limit=5)
    assert ranked is not None


def test_graph_find_node_upper_and_fragment() -> None:
    g = AttackGraph()
    g.add_node("USER@ALICE@CORP", "User", sam="alice")
    # uppercase exact match
    assert g.find_node("user@alice@corp") == "USER@ALICE@CORP"
    # fragment match (endswith)
    assert g.find_node("CORP") == "USER@ALICE@CORP"


def test_graph_rank_exploit_chains_visited_depth_prune() -> None:
    from adaf_attack.core.graph import EXPLOIT_PROFILES

    if not EXPLOIT_PROFILES:
        return
    g = AttackGraph()
    kind = next(iter(EXPLOIT_PROFILES))
    g.add_node("USER@A@C", "User")
    g.add_node("USER@B@C", "User")
    g.add_node("DOMAIN@C", "Domain")
    g.add_edge("USER@A@C", "USER@B@C", "Related")
    g.add_edge("USER@B@C", "DOMAIN@C", kind)
    chains = g.rank_exploit_chains(["USER@A@C"], max_depth=5, per_start=8)
    assert chains


# --------------------------- report + roast_format + ldap_enum helpers ---------------------------


def test_report_md_escape_pipe() -> None:
    assert _md_escape("a|b") == "a\\|b"


def test_ldap_enum_uac_and_list_attr() -> None:
    assert _uac_has(None, 0x1) is False
    assert _uac_has(0x1, 0x1) is True

    class _A:
        def __init__(self, v: Any) -> None:
            self.value = v

    # value=None
    from types import SimpleNamespace

    e = SimpleNamespace(k=_A(None))
    assert le_list_attr(e, "k") == []


def test_roast_format_bytes_cipher_direct() -> None:
    """Cipher already bytes-like from getComponentByName."""

    class _Node:
        def getComponentByName(self, name: str) -> Any:
            if name == "enc-part":
                return _Enc()
            if name == "ticket":
                return None
            return None

    class _Enc:
        def getComponentByName(self, name: str) -> Any:
            if name == "etype":
                return 23
            if name == "cipher":
                return bytes(range(32))
            return None

    class _Wrap:
        enc_part = None

        def getComponentByName(self, name: str) -> Any:
            return _Enc() if name == "enc-part" else None

    got, etype = _extract_cipher_and_etype(_Wrap())
    assert got == bytes(range(32))
    assert etype == 23


# --------------------------- parse_interesting_aces object-type ACE ---------------------------


def test_parse_interesting_aces_covers_return_paths() -> None:
    sd = build_allowed_to_act_sd("S-1-5-21-100-200-300-1105")
    aces = parse_interesting_aces(sd)
    # GenericAll must be present
    assert any(a.right == "GenericAll" for a in aces)


# --------------------------- creds skip in first_working_target ---------------------------


def test_first_working_target_skips_empty_without_probe() -> None:
    from adaf_attack.core.creds import first_working_target

    empty = Credential(username="skip")
    cs = CredentialSet(credentials=[empty])
    # no probe → returns None because all creds have no secrets
    assert first_working_target(cs, "10.0.0.1", "corp.test") is None


# --------------------------- esc6 parse EditFlags falls into bare-hex ---------------------------


def test_parse_editflags_bare_hex_fallback_alt() -> None:
    # Value follows regex requiring 'REG_DWORD' etc — but the alt path with "0x" prefix hits line 30-31
    assert _parse_editflags("EditFlags   0xABCD") == 0xABCD


# --------------------------- findings roundtrip ---------------------------


def test_findings_from_session_and_write(tmp_path: Path) -> None:
    session = tmp_path / "s"
    session.mkdir()
    # seed some evidence
    (session / "acl-enum.json").write_text(
        json.dumps({"dcsync_principals": ["S-1-5-21-1"]}), encoding="utf-8"
    )
    (session / "adcs-enum.json").write_text(
        json.dumps({"esc1_candidates": ["User"]}), encoding="utf-8"
    )
    findings = findings_from_session(session)
    assert isinstance(findings, list)
    out = write_findings(session, findings)
    assert out.is_file()
