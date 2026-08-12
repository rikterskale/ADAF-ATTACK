"""RODC surface discovery — password replication policy, KRBTGT, delegation.

Read-only enumeration of Read-Only Domain Controllers, their allowed/denied
replication groups, principals allowed to authenticate, and RODC KRBTGT
accounts.  No credential extraction or forgery is performed here; results are
graph evidence for next-actions and reporting.
"""

from __future__ import annotations

import json
from typing import Any

from ldap3 import SUBTREE
from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

# UF_PARTIAL_SECRETS_ACCOUNT — marks an RODC computer account
UAC_PARTIAL_SECRETS = 0x04000000
# UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
UAC_TRUSTED_TO_AUTH = 0x01000000
# UF_TRUSTED_FOR_DELEGATION
UAC_TRUSTED_FOR_DELEG = 0x00080000

RODC_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "dNSHostName",
    "objectSid",
    "userAccountControl",
    "msDS-RevealOnDemandGroup",
    "msDS-NeverRevealGroup",
    "msDS-AuthenticatedAtDC",
    "managedBy",
    "primaryGroupID",
]

KRBTGT_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "objectSid",
    "userAccountControl",
    "msDS-SecondaryKrbTgtNumber",
]

DELEG_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "userAccountControl",
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
]


def _list_attr(entry: Any, name: str) -> list[str]:
    val = getattr(entry, name, None)
    if not val:
        return []
    raw = val.value if hasattr(val, "value") else val
    if raw is None:
        return []
    if isinstance(raw, list | tuple):
        return [str(x) for x in raw]
    return [str(raw)]


def _uac(entry: Any) -> int:
    try:
        return int(entry.userAccountControl.value) if entry.userAccountControl else 0
    except (TypeError, ValueError, AttributeError):
        return 0


@register_capability(
    id="rodc-delegation",
    summary="Enumerate RODC password-replication policy, KRBTGT, and delegation exposure",
    category="enumeration",
    tags=("rodc", "delegation", "krbtgt", "prp", "password-replication"),
)
class RodcDelegation:
    def run(
        self, target: Target, session: Session, graph: AttackGraph, **kwargs: Any
    ) -> dict[str, Any]:
        console.print(f"[bold]RODC / delegation[/bold] → {target.domain} @ {target.dc_ip}")
        conn, base_dn, _cfg = ldap_connect(target)

        result: dict[str, Any] = {
            "domain": target.domain,
            "rodc_computers": [],
            "rodc_krbtgt": [],
            "delegation": [],
            "notes": {
                "krbtgt_abuse": (
                    "RODC KRBTGT keys enable forged PACs scoped to that RODC's "
                    "password-replication policy. Extraction requires DCSync-class "
                    "rights or physical/backup access — not performed by this module."
                ),
                "allowed_to_authenticate": (
                    "msDS-AuthenticatedAtDC lists principals permitted to use this RODC."
                ),
            },
        }

        # --- RODC computer accounts (UF_PARTIAL_SECRETS_ACCOUNT) --------------
        conn.search(
            base_dn,
            "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=67108864))",
            search_scope=SUBTREE,
            attributes=RODC_ATTRS,
        )
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not sam:
                continue
            uac = _uac(entry)
            reveal = _list_attr(entry, "msDS-RevealOnDemandGroup")
            never = _list_attr(entry, "msDS-NeverRevealGroup")
            auth_at = _list_attr(entry, "msDS-AuthenticatedAtDC")
            item = {
                "sam": sam,
                "dn": str(entry.distinguishedName),
                "dns": str(entry.dNSHostName) if entry.dNSHostName else None,
                "uac": uac,
                "partial_secrets": bool(uac & UAC_PARTIAL_SECRETS),
                "reveal_on_demand_groups": reveal,
                "never_reveal_groups": never,
                "authenticated_at_dc": auth_at,
                "managed_by": str(entry.managedBy) if entry.managedBy else None,
            }
            result["rodc_computers"].append(item)

            node = f"RODC@{sam.upper()}@{target.domain.upper()}"
            graph.add_node(
                node,
                "Computer",
                sam=sam,
                dn=item["dn"],
                rodc=True,
                dns=item["dns"],
            )
            domain_node = f"DOMAIN@{target.domain.upper()}"
            graph.add_node(domain_node, "Domain", name=target.domain)
            graph.add_edge(node, domain_node, "IsRODC")

            for group_dn in reveal:
                graph.add_edge(node, f"GROUPDN@{group_dn.upper()}", "RevealOnDemand")
            for group_dn in never:
                graph.add_edge(node, f"GROUPDN@{group_dn.upper()}", "NeverReveal")
            for principal in auth_at:
                graph.add_edge(
                    f"PRINCIPAL@{principal.upper()}",
                    node,
                    "AllowedToAuthenticateAtRODC",
                )

            console.print(
                f"  RODC [cyan]{sam}[/cyan]  reveal={len(reveal)}  "
                f"never={len(never)}  auth_principals={len(auth_at)}"
            )

        # --- RODC KRBTGT accounts (krbtgt_*) ---------------------------------
        conn.search(
            base_dn,
            "(&(objectClass=user)(sAMAccountName=krbtgt_*))",
            search_scope=SUBTREE,
            attributes=KRBTGT_ATTRS,
        )
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not sam:
                continue
            item = {
                "sam": sam,
                "dn": str(entry.distinguishedName),
                "secondary_krbtgt_number": (
                    int(entry["msDS-SecondaryKrbTgtNumber"].value)
                    if entry["msDS-SecondaryKrbTgtNumber"]
                    else None
                ),
            }
            result["rodc_krbtgt"].append(item)
            node = f"KRBTGT@{sam.upper()}@{target.domain.upper()}"
            graph.add_node(node, "User", sam=sam, dn=item["dn"], rodc_krbtgt=True)
            graph.add_edge(node, f"DOMAIN@{target.domain.upper()}", "RODCKrbtgt")
            console.print(f"  KRBTGT [cyan]{sam}[/cyan]  number={item['secondary_krbtgt_number']}")

        # --- Delegation exposure (unconstrained / constrained / RBCD signals) -
        conn.search(
            base_dn,
            "(|(objectClass=user)(objectClass=computer))",
            search_scope=SUBTREE,
            attributes=DELEG_ATTRS,
            size_limit=int(kwargs.get("max_objects") or 2000),
        )
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not sam:
                continue
            uac = _uac(entry)
            constrained = _list_attr(entry, "msDS-AllowedToDelegateTo")
            has_rbcd_raw = bool(entry.get("msDS-AllowedToActOnBehalfOfOtherIdentity", False))
            unconstrained = bool(uac & UAC_TRUSTED_FOR_DELEG)
            protocol_transition = bool(uac & UAC_TRUSTED_TO_AUTH)

            if not (unconstrained or constrained or has_rbcd_raw):
                continue

            item = {
                "account": sam,
                "dn": str(entry.distinguishedName),
                "unconstrained": unconstrained,
                "protocol_transition": protocol_transition,
                "constrained_spns": constrained,
                "has_rbcd_attribute": has_rbcd_raw,
            }
            result["delegation"].append(item)

            account_id = f"ACCOUNT@{sam.upper()}@{target.domain.upper()}"
            domain_id = f"DOMAIN@{target.domain.upper()}"
            graph.add_node(account_id, "User", sam=sam, dn=item["dn"])
            if unconstrained:
                graph.add_edge(account_id, domain_id, "UnconstrainedDelegation")
            if constrained:
                graph.add_edge(
                    account_id,
                    domain_id,
                    "AllowedToDelegate",
                    spns=constrained[:20],
                    protocol_transition=protocol_transition,
                )
                for spn in constrained[:10]:
                    graph.add_edge(account_id, f"SPN@{spn.upper()}", "CanDelegateTo")

        conn.unbind()

        result["count"] = (
            len(result["rodc_computers"]) + len(result["rodc_krbtgt"]) + len(result["delegation"])
        )
        session.path("rodc-delegation.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        graph.save(session.path("graph.json"))
        session.log(
            "rodc-delegation.complete",
            rodc=len(result["rodc_computers"]),
            krbtgt=len(result["rodc_krbtgt"]),
            delegation=len(result["delegation"]),
        )
        console.print(
            f"[green]Done[/green]  RODCs={len(result['rodc_computers'])}  "
            f"KRBTGT_={len(result['rodc_krbtgt'])}  "
            f"delegation={len(result['delegation'])}"
        )
        return result
