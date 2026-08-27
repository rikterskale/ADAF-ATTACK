"""Unit tests for core.command_templates."""

from __future__ import annotations

import pytest

from adaf_attack.core.command_templates import (
    COMMAND_TEMPLATES,
    SECONDARY_COMMAND_TEMPLATES,
    _sam_from_node_id,
    build_exploit_commands,
    shell_quote,
)
from adaf_attack.core.target import Target


def test_shell_quote_uses_posix_shlex_for_metacharacters() -> None:
    assert shell_quote("corp.local") == "corp.local"
    assert shell_quote("DC01$") == "DC01$"
    quoted = shell_quote("my domain")
    assert "'" in quoted or "\\" in quoted
    assert "my domain" in quoted or "my\\ domain" in quoted
    # Documented contract: POSIX quoting; PowerShell operators should read CLI_REFERENCE.
    assert "POSIX" in (shell_quote.__doc__ or "")
    assert "PowerShell" in (shell_quote.__doc__ or "")


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
    result = build_exploit_commands(chain, target)
    assert result and result[0]["fallback"] is True
    assert "adaf-attack plan UnknownRel" in result[0]["command"]


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


def test_unknown_placeholder_is_explicit_and_shell_safe(monkeypatch):
    """A missing template field remains visible without creating raw shell syntax."""
    raw = "run --thing {unresolved_placeholder}"
    monkeypatch.setitem(
        COMMAND_TEMPLATES,
        "BogusRel",
        [
            {
                "capability": "bogus",
                "risk": "low",
                "approval_required": "false",
                "cmd": raw,
            }
        ],
    )
    target = Target(domain="corp.local", dc_ip="10.0.0.1", username="op")
    chain = {
        "terminal_relation": "BogusRel",
        "start": "USER@alice@CORP.LOCAL",
        "end": "USER@bob@CORP.LOCAL",
    }
    examples = build_exploit_commands(chain, target)
    assert len(examples) == 1
    assert examples[0]["command"] == "run --thing '<unresolved_placeholder>'"


def test_service_spn_can_come_from_chain_evidence() -> None:
    target = Target(domain="corp.local", dc_ip="10.0.0.1", username="op")
    chain = {
        "terminal_relation": "WriteRBCD",
        "start": "COMPUTER@WS01$",
        "end": "COMPUTER@SQL01$",
        "service_class": "MSSQLSvc",
        "service_host": "sql01.corp.local:1433",
    }
    result = build_exploit_commands(chain, target)
    assert "--spn MSSQLSvc/sql01.corp.local:1433" in result[0]["command"]


def test_explicit_spn_override_is_quoted() -> None:
    target = Target(domain="corp example", dc_ip="10.0.0.1", username="operator one")
    chain = {
        "terminal_relation": "AllowedToAct",
        "start": "COMPUTER@WS01$",
        "end": "COMPUTER@DC01$",
    }
    result = build_exploit_commands(chain, target, spn="HTTP/dc01.corp example")
    assert "-P spn='HTTP/dc01.corp example'" in result[0]["command"]


def test_template_schema_and_filter_values_are_shell_safe() -> None:
    assert all(
        isinstance(template["approval_required"], bool)
        for templates in COMMAND_TEMPLATES.values()
        for template in templates
    )
    target = Target(domain="corp.local", dc_ip="10.0.0.1", username="op")
    result = build_exploit_commands(
        {
            "terminal_relation": "ReadLAPSPassword",
            "end": "COMPUTER@DC 01$",
        },
        target,
    )
    assert "computer_filter='(sAMAccountName=DC 01$)'" in result[0]["command"]


def test_hashcat_follow_ons_are_review_only_and_use_expected_modes() -> None:
    target = Target(domain="corp.local", dc_ip="10.0.0.1", username="op")
    result = build_exploit_commands(
        {
            "terminal_relation": "HasSPN",
            "start": "USER@alice@CORP.LOCAL",
            "end": "USER@alice@CORP.LOCAL",
        },
        target,
    )
    follow_ons = result[0]["follow_on_commands"]
    assert {item["kind"] for item in follow_ons} == {"hashcat"}
    assert "-m 13100" in follow_ons[0]["command"]
    assert "./kerberoast.hashes.txt" in follow_ons[0]["command"]
    assert all(item["review_only"] for item in follow_ons)


def test_ticket_import_follow_on_is_parameterized() -> None:
    target = Target(domain="corp.local", dc_ip="10.0.0.1", username="op")
    result = build_exploit_commands(
        {
            "terminal_relation": "HasKeyCredentialLink",
            "start": "USER@alice@CORP.LOCAL",
            "end": "USER@alice@CORP.LOCAL",
        },
        target,
    )
    follow_on = result[0]["follow_on_commands"][0]
    assert follow_on["kind"] == "ticket-import"
    assert "operation=import-ccache" in follow_on["command"]
    assert "artifact=./ticket.ccache" in follow_on["command"]


def test_secondary_template_registry_covers_cracking_and_imports() -> None:
    assert "HasSPN" in SECONDARY_COMMAND_TEMPLATES
    assert "CanASREP" in SECONDARY_COMMAND_TEMPLATES
    assert "AllowedToAct" in SECONDARY_COMMAND_TEMPLATES


@pytest.mark.parametrize(
    "relation,capability,needs_force",
    [
        ("GenericAll", "acl-abuse", True),
        ("ForceChangePassword", "force-change-password", True),
        ("HasSession", "session-abuse", False),
        ("AdminTo", "local-admin", False),
        ("ESC2", "esc-chain", True),
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
