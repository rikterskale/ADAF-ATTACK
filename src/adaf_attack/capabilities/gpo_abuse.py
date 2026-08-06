"""GPO abuse surface — writable GPOs, links, and high-value SD edges."""

from __future__ import annotations

import json
from typing import Any

from ldap3 import SUBTREE
from rich.console import Console

from adaf_attack.core.acl import fetch_sd, parse_interesting_aces
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

GPO_ATTRS = [
    "displayName",
    "cn",
    "distinguishedName",
    "gPCFileSysPath",
    "flags",
    "versionNumber",
]
# gplink on OUs / domain / sites
LINK_FILTER = "(|(objectClass=organizationalUnit)(objectClass=domain)(objectClass=site))"


@register_capability(
    id="gpo-abuse",
    summary="Enumerate writable GPOs, GPO links, and abuse-relevant ACL edges",
    category="privilege-escalation",
    tags=("gpo", "group-policy", "abuse", "acl"),
)
class GpoAbuse:
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
        console.print(f"[bold]GPO abuse[/bold] → {target.domain} @ {target.dc_ip}")
        conn, base_dn, config_nc = ldap_connect(target)

        result: dict[str, Any] = {
            "domain": target.domain,
            "gpos": [],
            "writable_gpos": [],
            "links": [],
        }

        conn.search(
            base_dn,
            "(objectClass=groupPolicyContainer)",
            search_scope=SUBTREE,
            attributes=GPO_ATTRS,
        )
        for entry in conn.entries:
            cn = str(entry.cn) if entry.cn else None
            display = str(entry.displayName) if entry.displayName else cn
            if not cn:
                continue
            dn = str(entry.distinguishedName)
            gpo = {
                "cn": cn,
                "display_name": display,
                "dn": dn,
                "sysvol": str(entry.gPCFileSysPath) if entry.gPCFileSysPath else None,
                "flags": int(entry.flags.value) if entry.flags else None,
                "version": int(entry.versionNumber.value) if entry.versionNumber else None,
                "writers": [],
            }
            gpo_id = f"GPO@{cn.upper()}@{target.domain.upper()}"
            graph.add_node(gpo_id, "GPO", cn=cn, display_name=display, dn=dn, sysvol=gpo["sysvol"])

            sd = fetch_sd(conn, dn)
            if sd:
                try:
                    for ace in parse_interesting_aces(sd):
                        if ace.right in (
                            "GenericAll",
                            "GenericWrite",
                            "WriteDacl",
                            "WriteOwner",
                            "WriteProperty",
                            "CreateChild",
                        ):
                            gpo["writers"].append({"sid": ace.principal_sid, "right": ace.right})
                            src = f"SID@{ace.principal_sid}"
                            graph.add_node(src, "Base", sid=ace.principal_sid)
                            graph.add_edge(src, gpo_id, "WriteGPO", right=ace.right)
                except Exception:  # noqa: BLE001
                    pass

            result["gpos"].append(gpo)
            if gpo["writers"]:
                result["writable_gpos"].append(
                    {
                        "cn": cn,
                        "display_name": display,
                        "writers": gpo["writers"],
                        "sysvol": gpo["sysvol"],
                    }
                )
                console.print(
                    f"  [red]Writable GPO[/red]  {display}  writers={len(gpo['writers'])}"
                )
            else:
                console.print(f"  GPO  {display}")

        # GPO links on domain + OUs
        try:
            conn.search(
                base_dn,
                "(|(objectClass=organizationalUnit)(objectClass=domainDNS))",
                search_scope=SUBTREE,
                attributes=["distinguishedName", "gPLink", "name"],
            )
            for entry in conn.entries:
                gplink = str(entry.gPLink) if entry.gPLink else None
                if not gplink:
                    continue
                link = {
                    "container": str(entry.distinguishedName),
                    "name": str(entry.name) if entry.name else None,
                    "gplink": gplink[:500],
                }
                result["links"].append(link)
                # Parse [LDAP://cn={GUID},...;flags] fragments loosely
                if "CN={" in gplink.upper() or "cn={" in gplink:
                    graph.add_edge(
                        f"CONTAINER@{link['container']}",
                        f"DOMAIN@{target.domain.upper()}",
                        "GPLink",
                    )
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]GPLink enum limited: {exc}[/yellow]")

        conn.unbind()
        out_path = session.path("gpo-abuse.json")
        out_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "gpo-abuse.complete",
            gpos=len(result["gpos"]),
            writable=len(result["writable_gpos"]),
            links=len(result["links"]),
        )
        console.print(
            f"[green]Done[/green]  gpos={len(result['gpos'])}  "
            f"writable={len(result['writable_gpos'])}  links={len(result['links'])}"
        )
        console.print(f"Results → {out_path}")
        return result
