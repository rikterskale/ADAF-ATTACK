"""Experimental offensive capabilities registered for tracking only.

These IDs appear in `list-capabilities`, the live matrix, and path templates.
Runners do not touch the target; they write a tracking evidence file so
operators can plan work. Status in LIVE_CAPABILITY_MATRIX.json is
``experimental`` until a real implementation replaces the stub.
"""

from __future__ import annotations

import json
from typing import Any

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

# id, summary, destructive, category, tags, environment, tools, fixture
PLANNED_CAPABILITIES: tuple[tuple[str, str, bool, str, tuple[str, ...], str, tuple[str, ...], str], ...] = (
    (
        "add-member",
        "Add a principal to a group (AddMember / GenericAll on group)",
        True,
        "privilege-escalation",
        ("acl", "group"),
        "live-mutating",
        (),
        "delegated-acl-target",
    ),
    (
        "add-self",
        "Add the current principal to a group (AddSelf)",
        True,
        "privilege-escalation",
        ("acl", "group"),
        "live-mutating",
        (),
        "delegated-acl-target",
    ),
    (
        "force-change-password",
        "Reset a user password via User-Force-Change-Password",
        True,
        "credential-access",
        ("acl", "password"),
        "live-mutating",
        (),
        "delegated-acl-target",
    ),
    (
        "acl-abuse",
        "Operator ACL abuse: GenericAll / GenericWrite / WriteDacl / WriteOwner / Owns",
        True,
        "privilege-escalation",
        ("acl",),
        "live-mutating",
        (),
        "delegated-acl-target",
    ),
    (
        "write-spn",
        "Set or clear servicePrincipalName for targeted Kerberoast",
        True,
        "credential-access",
        ("spn", "kerberoast"),
        "live-mutating",
        (),
        "delegated-acl-target",
    ),
    (
        "unconstrained-delegation",
        "Hunt computers trusted for unconstrained delegation (TGT delegation)",
        False,
        "enumeration",
        ("kerberos", "delegation"),
        "live-read-only",
        (),
        "baseline-directory",
    ),
    (
        "constrained-delegation",
        "Abuse constrained delegation (msDS-AllowedToDelegateTo)",
        True,
        "lateral-movement",
        ("kerberos", "delegation"),
        "live-mutating",
        ("impacket",),
        "delegated-service",
    ),
    (
        "badsuccessor",
        "Windows Server 2025 dMSA BadSuccessor privilege escalation",
        True,
        "privilege-escalation",
        ("dmsa", "windows-server-2025"),
        "live-mutating",
        (),
        "dmsa-lab",
    ),
    (
        "dmsa-ouroboros",
        "Post-patch dMSA Ouroboros credential extraction (Server 2025)",
        True,
        "credential-access",
        ("dmsa", "windows-server-2025"),
        "live-mutating",
        (),
        "dmsa-lab",
    ),
    (
        "esc9",
        "AD CS ESC9: template with no SID security extension",
        True,
        "adcs",
        ("adcs", "esc"),
        "live-mutating",
        ("certipy",),
        "adcs-lab",
    ),
    (
        "esc10",
        "AD CS ESC10: weak certificate mapping",
        True,
        "adcs",
        ("adcs", "esc"),
        "live-mutating",
        ("certipy",),
        "adcs-lab",
    ),
    (
        "esc13",
        "AD CS ESC13: issuance policy linked to a privileged group",
        True,
        "adcs",
        ("adcs", "esc"),
        "live-mutating",
        ("certipy",),
        "adcs-lab",
    ),
    (
        "esc14",
        "AD CS ESC14: weak explicit certificate mapping",
        True,
        "adcs",
        ("adcs", "esc"),
        "live-mutating",
        ("certipy",),
        "adcs-lab",
    ),
    (
        "esc15",
        "AD CS ESC15 (EKUwu / CVE-2024-49019): v1 template application policy override",
        True,
        "adcs",
        ("adcs", "esc"),
        "live-mutating",
        ("certipy",),
        "adcs-lab",
    ),
    (
        "esc16",
        "AD CS ESC16: security extension disabled on the CA",
        True,
        "adcs",
        ("adcs", "esc"),
        "live-mutating",
        ("certipy",),
        "adcs-lab",
    ),
    (
        "krb-relay",
        "Kerberos relay / reflection into LDAP, SMB, or HTTP",
        True,
        "lateral-movement",
        ("kerberos", "relay"),
        "live-mutating",
        ("impacket",),
        "relay-lab",
    ),
    (
        "golden-cert",
        "Forge authentication certificates from a stolen CA key",
        True,
        "persistence",
        ("adcs", "certificate"),
        "live-mutating",
        ("certipy",),
        "adcs-lab",
    ),
    (
        "dpapi-domain-backup",
        "Retrieve the domain DPAPI backup key via replication rights",
        False,
        "credential-access",
        ("dpapi", "dcsync"),
        "live-read-only",
        ("impacket",),
        "delegated-replication",
    ),
    (
        "maq-rbcd-workflow",
        "MachineAccountQuota add-computer then RBCD then S4U",
        True,
        "lateral-movement",
        ("maq", "rbcd", "workflow"),
        "live-mutating",
        ("impacket",),
        "delegated-computer",
    ),
    (
        "nopac-workflow",
        "sAMAccountName spoof (noPac / CVE-2021-42278/42287) workflow",
        True,
        "privilege-escalation",
        ("nopac", "cve", "workflow"),
        "live-mutating",
        ("impacket",),
        "unpatched-dc",
    ),
    (
        "targeted-kerberoast",
        "Write SPN, Kerberoast, revert SPN",
        True,
        "credential-access",
        ("kerberoast", "spn", "workflow"),
        "live-mutating",
        ("impacket",),
        "delegated-acl-target",
    ),
    (
        "dcsync-grant-workflow",
        "Grant DS-Replication rights, DCSync, revert the ACE",
        True,
        "credential-access",
        ("dcsync", "acl", "workflow"),
        "live-mutating",
        ("impacket",),
        "delegated-acl-target",
    ),
    (
        "esc8-relay-workflow",
        "Coerce plus HTTP relay to AD CS web enrollment (ESC8)",
        True,
        "adcs",
        ("adcs", "esc8", "relay", "workflow"),
        "live-mutating",
        ("impacket", "certipy"),
        "adcs-lab",
    ),
    (
        "unconst-tgtdump-workflow",
        "Unconstrained-delegation hunt then coerce to capture a TGT",
        True,
        "credential-access",
        ("delegation", "coerce", "workflow"),
        "live-mutating",
        ("impacket",),
        "unconstrained-computer",
    ),
    (
        "adminsdholder-persist",
        "Plant a persistence ACE on AdminSDHolder",
        True,
        "persistence",
        ("acl", "adminsdholder"),
        "live-mutating",
        (),
        "domain-admin-lab",
    ),
    (
        "sidhistory-inject",
        "Inject SID History / ExtraSids on a controlled principal",
        True,
        "privilege-escalation",
        ("sidhistory", "trust"),
        "live-mutating",
        (),
        "trust-lab",
    ),
    (
        "pre2k-spray",
        "Pre-Windows 2000 compatible computer accounts (password = sAMAccountName)",
        False,
        "credential-access",
        ("pre2k", "spray"),
        "live-read-only",
        (),
        "baseline-directory",
    ),
    (
        "timeroast",
        "Unauthenticated RID roast via NTP (Timeroasting)",
        False,
        "credential-access",
        ("ntp", "roast"),
        "live-read-only",
        (),
        "baseline-directory",
    ),
    (
        "maq-add-computer",
        "Create a machine account using ms-DS-MachineAccountQuota",
        True,
        "privilege-escalation",
        ("maq", "computer"),
        "live-mutating",
        (),
        "baseline-directory",
    ),
    (
        "gmsa-read",
        "Read and parse msDS-ManagedPassword for a gMSA",
        False,
        "credential-access",
        ("gmsa",),
        "live-read-only",
        (),
        "gmsa-laps",
    ),
    (
        "trustedtoauth",
        "Protocol-transition constrained delegation (TrustedToAuthForDelegation)",
        False,
        "lateral-movement",
        ("kerberos", "delegation"),
        "live-read-only",
        ("impacket",),
        "delegated-service",
    ),
    (
        "dcshadow",
        "DCShadow replication-based directory modification",
        True,
        "persistence",
        ("replication", "dcshadow"),
        "live-mutating",
        ("impacket",),
        "disposable-dc",
    ),
    (
        "adidns-wpad",
        "Plant WPAD / wildcard records in AD-integrated DNS",
        True,
        "lateral-movement",
        ("dns", "wpad"),
        "live-mutating",
        (),
        "dns-lab",
    ),
    (
        "dnsadmin-srv",
        "DNSAdmins name-abuse (SRV / WPAD) without a server DLL drop",
        True,
        "privilege-escalation",
        ("dns", "dnsadmins"),
        "live-mutating",
        (),
        "dns-lab",
    ),
    (
        "sccm-enum",
        "Enumerate Microsoft Configuration Manager (SCCM/MECM) attack surface",
        False,
        "enumeration",
        ("sccm",),
        "live-read-only",
        (),
        "sccm-lab",
    ),
    (
        "sccm-naa",
        "Recover SCCM Network Access Account credentials",
        False,
        "credential-access",
        ("sccm", "naa"),
        "live-read-only",
        (),
        "sccm-lab",
    ),
    (
        "sccm-takeover",
        "SCCM site takeover via relay to the site database (TAKEOVER-1)",
        True,
        "privilege-escalation",
        ("sccm", "relay"),
        "live-mutating",
        ("impacket",),
        "sccm-lab",
    ),
    (
        "sccm-client-push",
        "Abuse SCCM client-push installation account",
        True,
        "lateral-movement",
        ("sccm",),
        "live-mutating",
        (),
        "sccm-lab",
    ),
    (
        "azureadssoacc-roast",
        "Kerberoast the Seamless SSO computer account (AZUREADSSOACC$)",
        False,
        "credential-access",
        ("hybrid", "kerberoast", "seamless-sso"),
        "live-read-only",
        ("impacket",),
        "hybrid-lab",
    ),
    (
        "aadconnect-dcsync",
        "Identify and use Azure AD Connect MSOL_* replication rights",
        False,
        "credential-access",
        ("hybrid", "dcsync", "aadconnect"),
        "live-read-only",
        ("impacket",),
        "hybrid-lab",
    ),
)


# First implementation PR — ldap3 + existing runners. Tag: next-pr
NEXT_PR_IDS: frozenset[str] = frozenset(
    {
        "add-member",
        "add-self",
        "write-spn",
        "targeted-kerberoast",
        "maq-add-computer",
        "maq-rbcd-workflow",
        "gmsa-read",
        "badsuccessor",
        "dcsync-grant-workflow",
        "pre2k-spray",
        "unconstrained-delegation",
    }
)

# Follow-on implementations that fit the current stack. Tag: wave-2
WAVE2_IDS: frozenset[str] = frozenset(
    {
        "force-change-password",
        "acl-abuse",
        "adminsdholder-persist",
        "timeroast",
        "adidns-wpad",
        "constrained-delegation",
        "trustedtoauth",
        "dpapi-domain-backup",
        "azureadssoacc-roast",
        "aadconnect-dcsync",
        "esc8-relay-workflow",
        "dmsa-ouroboros",
    }
)


def planned_ids() -> tuple[str, ...]:
    return tuple(item[0] for item in PLANNED_CAPABILITIES)


def planned_destructive_ids() -> tuple[str, ...]:
    return tuple(item[0] for item in PLANNED_CAPABILITIES if item[2])


def next_pr_ids() -> tuple[str, ...]:
    return tuple(sorted(NEXT_PR_IDS))


def wave2_ids() -> tuple[str, ...]:
    return tuple(sorted(WAVE2_IDS))


def _queue_tags(capability_id: str) -> tuple[str, ...]:
    extra: tuple[str, ...] = ()
    if capability_id in NEXT_PR_IDS:
        extra += ("next-pr",)
    if capability_id in WAVE2_IDS:
        extra += ("wave-2",)
    return extra


def _tracking_payload(capability_id: str, summary: str, target: Target, force: bool) -> dict[str, Any]:
    return {
        "ok": False,
        "implemented": False,
        "status": "experimental",
        "capability": capability_id,
        "summary": summary,
        "force": force,
        "domain": target.domain,
        "message": (
            "Registered for tracking only. This capability has no live "
            "implementation yet and made no changes to the target."
        ),
    }


def _attach(capability_id: str, summary: str) -> type:
    class PlannedOffensive:
        def run(
            self,
            target: Target,
            session: Session,
            graph: AttackGraph,
            *,
            force: bool = False,
            include_secrets: bool = False,
            **kwargs: Any,
        ) -> dict[str, Any]:
            result = _tracking_payload(capability_id, summary, target, force)
            session.path(f"{capability_id}.json").write_text(
                json.dumps(result, indent=2) + "\n",
                encoding="utf-8",
            )
            session.log(f"{capability_id}.tracking", implemented=False)
            return result

    class_name = "".join(part.title() for part in capability_id.split("-")) + "Tracking"
    PlannedOffensive.__name__ = class_name
    PlannedOffensive.__qualname__ = class_name
    PlannedOffensive.__doc__ = summary
    return PlannedOffensive


for (
    cap_id,
    summary,
    destructive,
    category,
    tags,
    _environment,
    _tools,
    _fixture,
) in PLANNED_CAPABILITIES:
    register_capability(
        id=cap_id,
        summary=summary,
        destructive=destructive,
        category=category,
        tags=(*tags, "experimental", "tracking", *_queue_tags(cap_id)),
    )(_attach(cap_id, summary))
