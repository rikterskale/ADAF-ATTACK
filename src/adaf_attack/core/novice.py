"""Plain-language safety and guidance used by the novice operator experience."""

from __future__ import annotations

from typing import Any

from adaf_attack.core.capability_help_data import capability_option_spec
from adaf_attack.core.registry import Capability

_GLOSSARY = {
    "kerberoast": "A request for service-account tickets that can be checked offline for weak passwords.",
    "dcsync": "A replication request that can expose password material; use only with explicit approval.",
    "rbcd": "A delegation setting that can let one computer act on behalf of a user to another service.",
    "spn": "A service name in Active Directory that tells Kerberos where a service is running.",
    "tgt": "A Kerberos Ticket Granting Ticket, used to request service tickets.",
}


def safety_summary(cap: Capability) -> dict[str, str | bool]:
    """Return independent safety facts rather than a misleading single color."""
    network = cap.category not in {"analysis", "export"}
    if cap.destructive:
        level, plain = "RED", "Can change a target when its write options are used."
    elif network:
        level, plain = (
            "YELLOW",
            "Reads information from an authorized target and contacts the network.",
        )
    else:
        level, plain = "GREEN", "Works from saved evidence and does not contact a target."
    return {"level": level, "network": network, "plain": plain}


def plain_description(cap: Capability) -> str:
    safety = safety_summary(cap)
    return f"{cap.summary}. {safety['plain']}"


def beginner_next_actions(cap: Capability) -> list[dict[str, str]]:
    from adaf_attack.core.ux import suggested_next_actions

    actions: list[dict[str, str]] = []
    for capability_id in suggested_next_actions(cap, limit=3):
        actions.append(
            {
                "id": capability_id,
                "message": f"Next, review {capability_id} to build on the evidence you just collected.",
            }
        )
    return actions


def explain_finding(finding: dict[str, Any]) -> str:
    title = str(finding.get("title") or finding.get("id") or "This finding")
    severity = str(finding.get("severity") or "unknown").lower()
    return f"{title} is rated {severity}. Review its evidence and remediation before making any change."


def glossary_definition(term: str) -> str | None:
    return _GLOSSARY.get(term.strip().lower())


# Plain-language prompts for the interactive `run` mode. Keys are the option
# flag as recorded in capability_option_spec; values describe the field in
# terms a novice can answer without reading the man page.
_PROMPT_LABELS: dict[str, dict[str, str]] = {
    "--domain": {
        "label": "Authorized domain (e.g. corp.local)",
        "help": "The Active Directory DNS domain you are cleared to test.",
    },
    "--dc-ip": {
        "label": "Domain controller IP or hostname",
        "help": "Reachable address of the DC you will query.",
    },
    "--username": {
        "label": "Username (optional; leave blank for anonymous)",
        "help": "sAMAccountName or UPN of the authorized account.",
    },
    "--password": {
        "label": "Password (input hidden; blank if using hash/ticket)",
        "help": "Only supply one of --password, --hashes, --aes-key, or --ccache.",
    },
    "--hashes": {
        "label": "NT hash or LM:NT (optional)",
        "help": "Used for pass-the-hash. Example: :aad3b435...",
    },
    "--ccache": {
        "label": "Kerberos ccache path (optional)",
        "help": "Existing TGT/TGS file. Sets KRB5CCNAME for you.",
    },
    "--sam": {
        "label": "Target sAMAccountName",
        "help": "The AD object (user or computer) this capability operates on.",
    },
    "--template": {
        "label": "AD CS certificate template name",
        "help": "Must exactly match the template display name on the CA.",
    },
    "--ca": {
        "label": "Certificate Authority name",
        "help": "e.g. CORP-CA. Use adcs-enum first if you do not know it.",
    },
    "--write-target": {
        "label": "DN of the object to modify",
        "help": "The exact distinguishedName that will receive the write.",
    },
    "--descriptor-hex": {
        "label": "Security descriptor as hex",
        "help": "Bring the pre-approved raw ACL descriptor for this write.",
    },
    "--set-on": {
        "label": "RBCD victim computer sAMAccountName",
        "help": "The computer object whose msDS-AllowedToActOnBehalf will be set.",
    },
    "--set-from": {
        "label": "RBCD source principal sAMAccountName",
        "help": "The controlled principal that will be granted delegation.",
    },
    "--gpo": {
        "label": "Target GPO GUID or display name",
        "help": "Identifier of the Group Policy Object to modify.",
    },
    "--payload": {
        "label": "Payload (inline text or @/path/to/file)",
        "help": "@path reads from a file; inline text is written verbatim.",
    },
    "--operation": {
        "label": "Ticket lifecycle operation",
        "help": "One of: import-ccache, export-ccache, import-pfx, export-pfx, pem-to-pfx, pfx-to-pem.",
    },
    "--alt-name": {
        "label": "Alternative name (UPN or DNS) for the cert (optional)",
        "help": "For ESC1-style enrollment; leave blank when not applicable.",
    },
    "--force": {
        "label": "Type YES to confirm this destructive capability",
        "help": "Destructive capabilities require explicit acknowledgement.",
    },
}


def prompt_spec_for_option(option_flag: str) -> dict[str, str]:
    """Return {label, help} for the plain-language prompt of an option flag.

    Also handles the -P key=value form used by newer capabilities by
    stripping the sentinel and offering a generic label.
    """
    if option_flag in _PROMPT_LABELS:
        return dict(_PROMPT_LABELS[option_flag])
    if option_flag.startswith("-P "):
        # E.g. "-P sam=<user>" → prompt for the key with the sample as help.
        remainder = option_flag[3:]
        key, _, sample = remainder.partition("=")
        return {
            "label": f"Value for parameter '{key}'",
            "help": f"Provide the value for -P {key}. Example: {sample or 'string'}.",
        }
    # Universal fallback so we never fail to prompt for a required option.
    return {
        "label": f"Value for option {option_flag}",
        "help": f"Provide the required value for {option_flag}.",
    }


def required_prompts(cap: Capability) -> list[dict[str, str]]:
    """List required options for a capability with plain-language prompts.

    Each entry is {option, label, help, is_param, param_key}. `is_param`
    marks entries that must be forwarded via -P key=value.
    """
    spec = capability_option_spec(cap.id, cap.destructive)
    prompts: list[dict[str, str]] = []
    for option in spec.required:
        info = prompt_spec_for_option(option)
        is_param = option.startswith("-P ")
        param_key = ""
        if is_param:
            remainder = option[3:]
            param_key = remainder.split("=", 1)[0]
        prompts.append(
            {
                "option": option,
                "label": info["label"],
                "help": info["help"],
                "is_param": "true" if is_param else "",
                "param_key": param_key,
            }
        )
    return prompts
