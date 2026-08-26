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
    "opsec": "Operational security: reducing unnecessary noise, exposure, and detectable activity.",
    "s4u": "A Kerberos protocol extension used to request a service ticket on behalf of another user.",
    "esc": "An AD CS escalation path caused by certificate-template or CA configuration weaknesses.",
    "pkinit": "Certificate-based Kerberos pre-authentication that yields a TGT from a client cert.",
    "unpac": "Recovering an NT hash from PAC_CREDENTIAL_INFO after a PKINIT TGT (UnPAC-the-Hash).",
    "asrep key": "The AS-REP encryption key from PKINIT; needed to decrypt PAC credential material.",
    "dcshadow": "Registering a rogue DC object and pushing directory changes via DRSUAPI replication.",
    "golden cert": "A client certificate forged with a stolen CA key, usually for PKINIT as any user.",
    "pac_credential_info": "PAC buffer type 2 that can carry NT/LM hashes after PKINIT authentication.",
}


def safety_summary(cap: Capability) -> dict[str, str | bool]:
    """Return independent safety facts rather than a misleading single color."""
    network = bool(cap.safety and cap.safety.network_side_effect) or cap.category not in {
        "analysis",
        "export",
    }
    if cap.safety and cap.safety.modifies_directory:
        level, plain = "RED", "Can change target state and requires explicit approval."
    elif cap.requires_force:
        level, plain = "RED", "Causes an approved network side effect or credential exposure."
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


def capability_difficulty(cap: Capability) -> dict[str, str]:
    """Classify a capability with labels a first-time operator can use."""
    spec = capability_option_spec(cap.id, cap.requires_force)
    required_count = len(spec.required)
    if cap.requires_force or required_count >= 5:
        level = "Advanced"
        reason = "Requires extra approval, exact target values, or target-state changes."
    elif cap.category in {"credential-access", "privilege-escalation", "lateral-movement"}:
        level = "Intermediate"
        reason = "Uses live-target context or security concepts worth reviewing first."
    elif cap.category in {"analysis", "export"}:
        level = "Beginner"
        reason = "Works mostly from saved evidence and is safe to explore."
    else:
        level = "Beginner"
        reason = "Has a short option set and is suitable after target preflight."
    return {"level": level, "reason": reason}


def home_actions(*, first_run: bool) -> list[dict[str, str]]:
    """Plain-language starting points for users who do not know the command names."""
    actions = [
        {
            "goal": "Check my installation",
            "command": "adaf-attack doctor --profile user-readiness --explain",
            "why": "Verifies Python, paths, and packaged demo files without touching a network.",
        },
        {
            "goal": "Try the safe offline demo",
            "command": "adaf-attack quickstart",
            "why": "Creates a disposable demo session and findings dashboard.",
        },
        {
            "goal": "Choose a beginner capability",
            "command": "adaf-attack list-capabilities --novice --safe-only",
            "why": "Shows only GREEN capabilities that do not contact a target.",
        },
        {
            "goal": "Review an authorized target",
            "command": "adaf-attack check --domain <domain> --dc-ip <dc>",
            "why": "Runs an explicit target preflight before any capability execution.",
        },
        {
            "goal": "Understand a finding",
            "command": "adaf-attack finding explain --session <session> --id <finding-id>",
            "why": "Explains the finding, evidence, severity, and next remediation step.",
        },
        {
            "goal": "Continue where I left off",
            "command": "adaf-attack sessions --limit 5",
            "why": "Shows recent sessions and their saved evidence status.",
        },
    ]
    if not first_run:
        actions.insert(
            2,
            {
                "goal": "Resume my workflow",
                "command": "adaf-attack session list --limit 5",
                "why": "Finds prior sessions before generating reports or next actions.",
            },
        )
    return actions


def command_option_explanations(cap: Capability) -> list[dict[str, str]]:
    """Explain every option shown in the beginner command builder."""
    spec = capability_option_spec(cap.id, cap.requires_force)
    explanations: list[dict[str, str]] = []
    for option in list(spec.required) + list(spec.optional):
        prompt = prompt_spec_for_option(option)
        explanations.append(
            {
                "option": option,
                "label": prompt["label"],
                "help": prompt["help"],
                "required": "true" if option in spec.required else "false",
            }
        )
    return explanations


def explain_finding(finding: dict[str, Any]) -> str:
    title = str(finding.get("title") or finding.get("id") or "This finding")
    severity = str(finding.get("severity") or "unknown").lower()
    return f"{title} is rated {severity}. Review its evidence and remediation before making any change."


def explain_finding_payload(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a structured, plain-English finding explanation."""
    finding_id = str(finding.get("id") or finding.get("finding_id") or "finding")
    title = str(finding.get("title") or finding.get("name") or finding_id)
    severity = str(finding.get("severity") or "unknown").lower()
    evidence = finding.get("evidence") or finding.get("evidence_refs") or []
    if isinstance(evidence, str):
        evidence = [evidence]
    if not isinstance(evidence, list):
        evidence = []
    why = {
        "critical": "A critical issue usually means direct or broad compromise is plausible.",
        "high": "A high issue can materially improve an attack path or expose sensitive access.",
        "medium": "A medium issue is worth tracking because it can combine with other weaknesses.",
        "low": "A low issue is usually a control gap or hardening opportunity.",
        "info": "An informational item adds context for reporting or later validation.",
    }.get(severity, "Severity was not recognized; review the evidence before acting.")
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "meaning": f"{title} is rated {severity}.",
        "why_it_matters": why,
        "evidence": evidence[:10],
        "recommended_next_step": "Validate the evidence, assign an owner, document the fix, then re-test.",
        "glossary": {
            term: definition
            for term, definition in glossary_items().items()
            if term in f"{finding_id} {title}".lower()
        },
    }


def remediation_checklist(finding: dict[str, Any]) -> dict[str, Any]:
    """Turn a finding into a beginner-friendly remediation checklist."""
    explained = explain_finding_payload(finding)
    return {
        "finding": explained,
        "steps": [
            {"id": "validate", "label": "Confirm the evidence is from the authorized scope."},
            {"id": "assign", "label": "Assign an owner who can change the affected control."},
            {"id": "fix", "label": "Apply the remediation or compensating control."},
            {"id": "document", "label": "Record the change, exception, or accepted risk."},
            {"id": "retest", "label": "Re-run the relevant validation and attach evidence."},
        ],
        "status": "not-started",
    }


def glossary_definition(term: str) -> str | None:
    """Resolve a glossary entry by short term or capability id."""
    key = term.strip().lower()
    if key in _GLOSSARY:
        return _GLOSSARY[key]
    # Capability ids → nearest glossary term (TUI help panel uses cap.id).
    aliases = {
        "unpac-the-hash": "unpac",
        "pkinit-auth": "pkinit",
        "shadow-pkinit-workflow": "pkinit",
        "dcshadow": "dcshadow",
        "golden-cert": "golden cert",
        "esc-chain": "esc",
        "rbcd-ticket-workflow": "rbcd",
        "s4u-abuse": "s4u",
        "dcsync": "dcsync",
        "kerberoast": "kerberoast",
    }
    mapped = aliases.get(key)
    return _GLOSSARY.get(mapped) if mapped else None


def glossary_items() -> dict[str, str]:
    """Return the shared glossary for CLI and TUI presentation."""
    return dict(sorted(_GLOSSARY.items()))


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
    "--impersonate": {
        "label": "User to impersonate (S4U)",
        "help": "sAMAccountName of the principal the service ticket should represent.",
    },
    "--spn": {
        "label": "Target SPN (e.g. cifs/app01.corp.local)",
        "help": "Service principal the S4U ticket will be requested for.",
    },
    "-P sam=<user>": {
        "label": "Certificate / account sAMAccountName",
        "help": "Subject account for PKINIT / UnPAC (usually matches the cert identity).",
    },
    "-P pfx=<path>": {
        "label": "PFX / PKCS#12 path",
        "help": "Client certificate+key bundle used for PKINIT or UnPAC.",
    },
    "-P asrep_key=<hex>": {
        "label": "AS-REP encryption key (hex)",
        "help": "Printed by gettgtpkinit after PKINIT; required for native U2U UnPAC.",
    },
    "-P ca_pfx=<stolen-ca.pfx>": {
        "label": "Stolen CA PFX path",
        "help": "CA private key material used to forge a golden certificate.",
    },
    "-P upn=<user@domain>": {
        "label": "UPN to forge into the certificate",
        "help": "Usually a privileged user@domain for PKINIT afterwards.",
    },
    "-P computer=<sam>": {
        "label": "Rogue / planted computer sAMAccountName",
        "help": "Computer account that will be registered as a temporary DC (DCShadow).",
    },
    "-P object=<dn>": {
        "label": "Directory object DN to push",
        "help": "Target DN for IDL_DRSAddEntry remote modify.",
    },
    "-P attribute=<name|oid>": {
        "label": "Attribute name or OID to push",
        "help": "LDAP display name (e.g. description) or dotted OID.",
    },
    "-P value=<data>": {
        "label": "Attribute value to push",
        "help": "New value written via DCShadow DRSAddEntry.",
    },
    "-P computer_password=<pass>": {
        "label": "Controlled computer password",
        "help": "Password for the RBCD source computer used to request S4U tickets.",
    },
    "-P computer_hashes=<LM:NT>": {
        "label": "Controlled computer NT hash (LM:NT or :NT)",
        "help": "Hash for the RBCD source computer when password is unavailable.",
    },
    "-P computer_ccache=<path>": {
        "label": "Controlled computer Kerberos ccache",
        "help": "Existing TGT for the RBCD source computer account.",
    },
    "-P esc=<1-16>": {
        "label": "ESC technique number (optional)",
        "help": "Force a specific ESC path (9-16 enroll, 8 relay, else cert-request).",
    },
    "-P template=<name>": {
        "label": "AD CS certificate template name",
        "help": "Must match a published template on the CA.",
    },
    "-P ca=<name>": {
        "label": "Certificate Authority name",
        "help": "e.g. CORP-CA. Discover with adcs-enum when unknown.",
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
    spec = capability_option_spec(cap.id, cap.requires_force)
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
