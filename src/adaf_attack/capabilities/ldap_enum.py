"""LDAP / domain enumeration capability.

Covers users, computers, groups, trusts, SPNs, constrained/unconstrained
delegation, SID history, and GPO links — all via shared ldap_connect auth.
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

USER_FILTER = "(&(objectCategory=person)(objectClass=user))"
COMPUTER_FILTER = "(objectCategory=computer)"
GROUP_FILTER = "(objectCategory=group)"
TRUST_FILTER = "(objectClass=trustedDomain)"
GPO_FILTER = "(objectClass=groupPolicyContainer)"

USER_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "memberOf",
    "servicePrincipalName",
    "userAccountControl",
    "adminCount",
    "description",
    "mail",
    "sidHistory",
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
]
COMPUTER_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "dNSHostName",
    "operatingSystem",
    "operatingSystemVersion",
    "servicePrincipalName",
    "userAccountControl",
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
]
GROUP_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "member",
    "adminCount",
    "description",
]
TRUST_ATTRS = ["name", "trustPartner", "trustDirection", "trustType", "flatName"]
GPO_ATTRS = [
    "displayName",
    "cn",
    "distinguishedName",
    "gPCFileSysPath",
    "flags",
]

# UAC bits
UAC_ACCOUNTDISABLE = 0x0002
UAC_DONT_REQ_PREAUTH = 0x400000
UAC_TRUSTED_FOR_DELEGATION = 0x80000  # unconstrained
UAC_NOT_DELEGATED = 0x100000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000  # constrained (protocol transition)


def _uac_has(uac: int | None, flag: int) -> bool:
    if uac is None:
        return False
    return bool(uac & flag)


def _list_attr(entry: Any, name: str) -> list[str]:
    val = getattr(entry, name, None)
    if not val:
        return []
    raw = val.value if hasattr(val, "value") else val
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return [str(x) for x in raw]
    return [str(raw)]


@register_capability(
    id="ldap-enum",
    summary=(
        "Enumerate users, computers, groups, trusts, SPNs, delegation, "
        "SID history, and GPO links via LDAP"
    ),
    category="enumeration",
    tags=("ldap", "enum", "users", "computers", "trusts", "spn", "delegation", "gpo"),
)
class LdapEnum:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        include_secrets: bool = False,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        console.print(f"[bold]LDAP enum[/bold] → {target.domain} @ {target.dc_ip}")

        conn, base_dn, _config = ldap_connect(target)

        domain_id = f"DOMAIN@{target.domain.upper()}"
        graph.add_node(domain_id, "Domain", name=target.domain, dn=base_dn)

        result: dict[str, Any] = {
            "domain": target.domain,
            "base_dn": base_dn,
            "users": [],
            "computers": [],
            "groups": [],
            "trusts": [],
            "spns": [],
            "delegation": [],
            "sid_history": [],
            "gpos": [],
        }

        # --- Users ---
        conn.search(base_dn, USER_FILTER, search_scope=SUBTREE, attributes=USER_ATTRS)
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not sam:
                continue
            uac = int(entry.userAccountControl.value) if entry.userAccountControl else None
            spns = _list_attr(entry, "servicePrincipalName")
            sid_hist = _list_attr(entry, "sidHistory")
            constrained = _list_attr(entry, "msDS-AllowedToDelegateTo")
            unconstrained = _uac_has(uac, UAC_TRUSTED_FOR_DELEGATION)
            proto_transition = _uac_has(uac, UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)

            user_id = f"USER@{sam.upper()}@{target.domain.upper()}"
            props = {
                "sam": sam,
                "dn": str(entry.distinguishedName),
                "admin_count": bool(entry.adminCount.value) if entry.adminCount else False,
                "disabled": _uac_has(uac, UAC_ACCOUNTDISABLE),
                "dont_req_preauth": _uac_has(uac, UAC_DONT_REQ_PREAUTH),
                "spns": spns,
                "sid_history": sid_hist,
                "unconstrained_delegation": unconstrained,
                "constrained_delegation": constrained,
                "protocol_transition": proto_transition,
            }
            graph.add_node(user_id, "User", **props)
            result["users"].append(props)

            for spn in spns:
                result["spns"].append({"account": sam, "spn": spn})
                graph.add_edge(user_id, user_id, "HasSPN", spn=spn)

            if props["dont_req_preauth"]:
                graph.add_edge(user_id, user_id, "CanASREP")

            if unconstrained:
                graph.add_edge(user_id, domain_id, "UnconstrainedDelegation")
                result["delegation"].append(
                    {"account": sam, "kind": "unconstrained", "target": target.domain}
                )

            for spn in constrained:
                graph.add_edge(user_id, f"SPN@{spn.upper()}", "AllowedToDelegate", spn=spn)
                result["delegation"].append(
                    {"account": sam, "kind": "constrained", "target": spn}
                )

            for sid in sid_hist:
                result["sid_history"].append({"account": sam, "sid": sid})
                graph.add_edge(user_id, f"SID@{sid}", "HasSIDHistory", sid=sid)

            for group_dn in entry.memberOf or []:
                graph.add_edge(user_id, f"GROUPDN@{group_dn}", "MemberOf")

        # --- Computers ---
        conn.search(base_dn, COMPUTER_FILTER, search_scope=SUBTREE, attributes=COMPUTER_ATTRS)
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not sam:
                continue
            uac = int(entry.userAccountControl.value) if entry.userAccountControl else None
            constrained = _list_attr(entry, "msDS-AllowedToDelegateTo")
            unconstrained = _uac_has(uac, UAC_TRUSTED_FOR_DELEGATION)
            computer_id = f"COMPUTER@{sam.upper()}@{target.domain.upper()}"
            props = {
                "sam": sam,
                "dn": str(entry.distinguishedName),
                "dns": str(entry.dNSHostName) if entry.dNSHostName else None,
                "os": str(entry.operatingSystem) if entry.operatingSystem else None,
                "spns": _list_attr(entry, "servicePrincipalName"),
                "unconstrained_delegation": unconstrained,
                "constrained_delegation": constrained,
            }
            graph.add_node(computer_id, "Computer", **props)
            result["computers"].append(props)

            if unconstrained:
                graph.add_edge(computer_id, domain_id, "UnconstrainedDelegation")
                result["delegation"].append(
                    {"account": sam, "kind": "unconstrained", "target": target.domain}
                )
            for spn in constrained:
                graph.add_edge(computer_id, f"SPN@{spn.upper()}", "AllowedToDelegate", spn=spn)
                result["delegation"].append(
                    {"account": sam, "kind": "constrained", "target": spn}
                )

        # --- Groups ---
        conn.search(base_dn, GROUP_FILTER, search_scope=SUBTREE, attributes=GROUP_ATTRS)
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not sam:
                continue
            group_id = f"GROUP@{sam.upper()}@{target.domain.upper()}"
            props = {
                "sam": sam,
                "dn": str(entry.distinguishedName),
                "admin_count": bool(entry.adminCount.value) if entry.adminCount else False,
            }
            graph.add_node(group_id, "Group", **props)
            result["groups"].append(props)

        # --- Trusts (lightweight; deep dive is trusts-enum) ---
        conn.search(base_dn, TRUST_FILTER, search_scope=SUBTREE, attributes=TRUST_ATTRS)
        for entry in conn.entries:
            props = {
                "name": str(entry.name) if entry.name else None,
                "partner": str(entry.trustPartner) if entry.trustPartner else None,
                "direction": int(entry.trustDirection.value) if entry.trustDirection else None,
                "type": int(entry.trustType.value) if entry.trustType else None,
            }
            result["trusts"].append(props)
            if props["partner"]:
                trust_id = f"DOMAIN@{props['partner'].upper()}"
                graph.add_node(trust_id, "Domain", name=props["partner"])
                graph.add_edge(domain_id, trust_id, "TrustedBy", direction=props["direction"])

        # --- GPOs ---
        try:
            conn.search(base_dn, GPO_FILTER, search_scope=SUBTREE, attributes=GPO_ATTRS)
            for entry in conn.entries:
                cn = str(entry.cn) if entry.cn else None
                display = str(entry.displayName) if entry.displayName else cn
                if not cn:
                    continue
                gpo_id = f"GPO@{cn.upper()}@{target.domain.upper()}"
                props = {
                    "cn": cn,
                    "display_name": display,
                    "dn": str(entry.distinguishedName),
                    "sysvol": str(entry.gPCFileSysPath) if entry.gPCFileSysPath else None,
                    "flags": int(entry.flags.value) if entry.flags else None,
                }
                graph.add_node(gpo_id, "GPO", **props)
                result["gpos"].append(props)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]GPO enum limited: {exc}[/yellow]")

        conn.unbind()

        out_path = session.path("ldap-enum.json")
        out_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))

        session.log(
            "ldap-enum.complete",
            users=len(result["users"]),
            computers=len(result["computers"]),
            groups=len(result["groups"]),
            trusts=len(result["trusts"]),
            spns=len(result["spns"]),
            delegation=len(result["delegation"]),
            sid_history=len(result["sid_history"]),
            gpos=len(result["gpos"]),
        )

        console.print(
            f"[green]Done[/green]  users={len(result['users'])}  "
            f"computers={len(result['computers'])}  groups={len(result['groups'])}  "
            f"trusts={len(result['trusts'])}  spns={len(result['spns'])}  "
            f"delegation={len(result['delegation'])}  "
            f"sidHistory={len(result['sid_history'])}  gpos={len(result['gpos'])}"
        )
        console.print(f"Results → {out_path}")
        return result
