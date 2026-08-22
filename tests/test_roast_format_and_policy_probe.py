"""Behavioral tests."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from adaf_attack.capabilities.adcs_policy_probe import AdcsPolicyProbe
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.roast_format import format_asrep_hashcat, format_tgs_hashcat
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def _ticket(cipher: bytes, etype: int) -> SimpleNamespace:
    return SimpleNamespace(enc_part=SimpleNamespace(cipher=cipher, etype=etype))


def test_roast_formatters_cover_rc4_aes_and_short_ticket_rejection() -> None:
    cipher = bytes(range(32))
    assert (
        "$krb5tgs$23$*svc$CORP.TEST$HTTP/app*$000102030405060708090a0b0c0d0e0f$"
        in format_tgs_hashcat("HTTP/app", "svc@corp.test", "corp.test", _ticket(cipher, 23))
    )
    assert "$krb5tgs$18$*svc$CORP.TEST$HTTP/app*" in format_tgs_hashcat(
        "HTTP/app", "svc", "corp.test", _ticket(cipher, 18)
    )
    assert "$krb5asrep$23$svc@CORP.TEST:" in format_asrep_hashcat(
        "svc@corp.test", "corp.test", _ticket(cipher, 23)
    )
    assert format_tgs_hashcat("HTTP/app", "svc", "corp.test", _ticket(b"short", 23)) is None


def test_adcs_policy_probe_records_authorized_evidence_and_requires_artifact(
    tmp_path: Path,
) -> None:
    session = Session(tmp_path / "sessions")
    graph = AttackGraph()
    target = Target(domain="corp.test", dc_ip="192.0.2.10")
    with pytest.raises(RuntimeError, match="requires --artifact"):
        AdcsPolicyProbe().run(target, session, graph)
    artifact = tmp_path / "policy.json"
    artifact.write_text(
        json.dumps(
            {
                "weak_certificate_mapping": True,
                "rpc_encryption_not_enforced": True,
                "issuance_policy_group_links": ["PolicyAdmins"],
            }
        ),
        encoding="utf-8",
    )

    result = AdcsPolicyProbe().run(target, session, graph, artifact=artifact)

    assert result == {
        "esc10_candidates": ["dc-policy"],
        "esc11_candidates": ["ca-rpc"],
        "esc13_candidates": ["PolicyAdmins"],
    }
    assert {edge.kind for edge in graph.edges} == {"ESC10", "ESC11", "ESC13"}
