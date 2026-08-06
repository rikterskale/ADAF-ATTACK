"""LDAP / domain enumeration capability."""

from __future__ import annotations

from typing import Any

from ldap3 import ALL, SUBTREE, Connection, Server
from ldap3.core.exceptions import LDAPException
from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

USER_FILTER = "(&(objectCategory=person)(objectClass=user))"
COMPUTER_FILTER = "(objectCategory=computer)"
GROUP_FILTER = "(objectCategory=group)"
TRUST_FILTER = "(objectClass=trustedDomain)"

USER_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "memberOf",
    "servicePrincipalName",
    "userAccountControl",
    "adminCount",
    "description",
    "mail",
]
COMPUTER_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "dNSHostName",
    "operatingSystem",
    "operatingSystemVersion",
    "servicePrincipalName",
    "userAccountControl",
]
GROUP_ATTRS = ["sAMAccountName", "distinguishedName", "member", "adminCount", "description"]
TRUST_ATTRS = ["name", "trustPartner", "trustDirection", "trustType", "flatName"]


def _uac_has(uac: int | None, flag: int) -> bool:
    if uac is None:
        return False
    return bool(uac & flag)


@register_capability(
    id="ldap-enum",
    summary="Enumerate domain users, computers, groups, trusts, and SPNs via LDAP",
    category="enumeration",
    tags=("ldap", "enum", "users", "computers", "trusts", "spn"),
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

        server = Server(target.dc_ip, get_info=ALL, use_ssl=target.ldaps)
        conn_kwargs: dict[str, Any] = {"auto_bind": True}

        if target.username and (target.password or target.hashes):
            user = target.auth_user or target.username
            if target.hashes:
                # ldap3 NTLM bind with hash is limited; prefer password for now
                console.print(
                    "[yellow]Hash bind via ldap3 is limited — prefer password for full enum[/yellow]"
                )
            conn = Connection(
                server,
                user=user,
                password=target.password or "",
                authentication="NTLM",
                **conn_kwargs,
            )
        else:
            console.print("[dim]Anonymous / unauthenticated bind[/dim]")
            conn = Connection(server, **conn_kwargs)

        try:
            if not conn.bind():
                raise RuntimeError(f"LDAP bind failed: {conn.result}")
        except LDAPException as exc:
            raise RuntimeError(f"LDAP connection error: {exc}") from exc

        base_dn = server.info.other.get("defaultNamingContext", [None])[0]
        if not base_dn:
            # fallback
            base_dn = ",".join(f"DC={p}" for p in target.domain.split("."))

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
        }

        # --- Users ---
        conn.search(base_dn, USER_FILTER, search_scope=SUBTREE, attributes=USER_ATTRS)
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not sam:
                continue
            uac = int(entry.userAccountControl.value) if entry.userAccountControl else None
            spns = [str(s) for s in (entry.servicePrincipalName or [])]
            user_id = f"USER@{sam.upper()}@{target.domain.upper()}"
            props = {
                "sam": sam,
                "dn": str(entry.distinguishedName),
                "admin_count": bool(entry.adminCount.value) if entry.adminCount else False,
                "disabled": _uac_has(uac, 0x2),
                "dont_req_preauth": _uac_has(uac, 0x400000),
                "spns": spns,
            }
            graph.add_node(user_id, "User", **props)
            result["users"].append(props)

            for spn in spns:
                result["spns"].append({"account": sam, "spn": spn})
                graph.add_edge(user_id, user_id, "HasSPN", spn=spn)

            if props["dont_req_preauth"]:
                graph.add_edge(user_id, user_id, "CanASREP")

            for group_dn in entry.memberOf or []:
                # resolve later if needed; store raw edge by DN for now
                graph.add_edge(user_id, f"GROUPDN@{group_dn}", "MemberOf")

        # --- Computers ---
        conn.search(base_dn, COMPUTER_FILTER, search_scope=SUBTREE, attributes=COMPUTER_ATTRS)
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not sam:
                continue
            computer_id = f"COMPUTER@{sam.upper()}@{target.domain.upper()}"
            props = {
                "sam": sam,
                "dn": str(entry.distinguishedName),
                "dns": str(entry.dNSHostName) if entry.dNSHostName else None,
                "os": str(entry.operatingSystem) if entry.operatingSystem else None,
                "spns": [str(s) for s in (entry.servicePrincipalName or [])],
            }
            graph.add_node(computer_id, "Computer", **props)
            result["computers"].append(props)

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

        # --- Trusts ---
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

        conn.unbind()

        out_path = session.path("ldap-enum.json")
        import json

        out_path.write_text(json.dumps(result, indent=2, default=str))
        graph.save(session.path("graph.json"))

        session.log(
            "ldap-enum.complete",
            users=len(result["users"]),
            computers=len(result["computers"]),
            groups=len(result["groups"]),
            trusts=len(result["trusts"]),
            spns=len(result["spns"]),
        )

        console.print(
            f"[green]Done[/green]  users={len(result['users'])}  "
            f"computers={len(result['computers'])}  groups={len(result['groups'])}  "
            f"trusts={len(result['trusts'])}  spns={len(result['spns'])}"
        )
        console.print(f"Results → {out_path}")
        return result
