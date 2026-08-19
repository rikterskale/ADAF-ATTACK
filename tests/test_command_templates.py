"""Unit tests for core.command_templates."""

from __future__ import annotations

import pytest

from adaf_attack.core.command_templates import (
    COMMAND_TEMPLATES,
    _sam_from_node_id,
    build_exploit_commands,
)
from adaf_attack.core.target import Target


def test_sam_from_node_id():
    assert _sam_from_node_id("USER@alice@CORP.LOCAL") == "alice"
    assert _sam_from_node_id("COMPUTER@DC01$") == "DC01$"
    assert _sam_from_node_id(None) == "<sam>"
    assert _sam_from_node_id("plain") == "plain"


def test_has_spn_produces_kerberoast_with_sam():
    target = Target(domain="corp.local", dc_ip="10.0.0.1", username="operator")
    chain = {
        "terminal_relation": "HasSPN",
        "start": "USER@alice@CORP.LOCAL",
        "end": "USER@alice@CORP.LOCAL",
        "impact": "Kerberoastable account",
        "score": 2.0,
    }
    examples = build_exploit_commands(chain, target, operator_user=target.username)
    assert len(examples) == 1
    cmd = examples[0]
    assert cmd["capability"] == "kerberoast"
    assert cmd["risk"] == "medium"
    assert cmd["approval_required"] is False
    assert "kerberoast" in cmd["command"]
    assert "sam=alice" in cmd["command"]
    assert "-d corp.local" in cmd["command"]
    assert "--dc-ip 10.0.0.1" in cmd["command"]
    assert "-u operator" in cmd["command"]


def test_dcsync_requires_approval():
    target = Target(domain="corp.local", dc_ip="10.0.0.1", username="operator")
    chain = {
        "terminal_relation": "DCSync",
        "start": "USER@admin@CORP.LOCAL",
        "end": "USER@admin@CORP.LOCAL",
    }
    examples = build_exploit_commands(chain, target)
    assert len(examples) == 1
    assert examples[0]["approval_required"] is True
    assert "--force" in examples[0]["command"]
    assert "sam=admin" in examples[0]["command"]


def test_unknown_relation_returns_empty():
    target = Target(domain="corp.local", dc_ip="10.0.0.1")
    chain = {"terminal_relation": "UnknownRel"}
    assert build_exploit_commands(chain, target) == []


def test_write_rbcd_placeholders():
    target = Target(domain="corp.local", dc_ip="10.0.0.1", username="op")
    chain = {
        "terminal_relation": "WriteRBCD",
        "start": "COMPUTER@WS01$",
        "end": "COMPUTER@DC01$",
    }
    examples = build_exploit_commands(chain, target)
    assert len(examples) == 1
    cmd = examples[0]["command"]
    assert "--set-on DC01$" in cmd
    assert "--set-from WS01$" in cmd
    assert "--spn cifs/DC01$" in cmd
    assert "--impersonate DC01$" in cmd


@pytest.mark.parametrize(
    "relation,capability,needs_force",
    [
        ("GenericAll", "acl-abuse", True),
        ("ForceChangePassword", "force-change-password", True),
        ("HasSession", "session-abuse", False),
        ("AdminTo", "local-admin", False),
        ("ESC2", "esc-chain", False),
        ("AllowedToDelegate", "constrained-delegation", True),
        ("DfscoerceOpen", "coerce", True),
        ("GetChanges", "dcsync", True),
    ],
)
def test_expanded_relations(relation, capability, needs_force):
    assert relation in COMMAND_TEMPLATES
    target = Target(domain="corp.local", dc_ip="10.0.0.1", username="op")
    chain = {
        "terminal_relation": relation,
        "start": "USER@alice@CORP.LOCAL",
        "end": "USER@bob@CORP.LOCAL",
    }
    examples = build_exploit_commands(chain, target)
    assert len(examples) >= 1
    ex = examples[0]
    assert ex["capability"] == capability
    assert ex["approval_required"] is needs_force
    if needs_force:
        assert "--force" in ex["command"]
