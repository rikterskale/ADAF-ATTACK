"""GPO abuse surface — writable GPOs, links, and impact-ranked abuse edges."""

from __future__ import annotations

import json
import re
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

GUID_RE = re.compile(r"CN=\{([0-9A-Fa-f-]{36})\}", re.IGNORECASE)


def _impact_score(
    *,
    writers: int,
    link_count: int,
    linked_to_domain: bool,
    linked_to_root_ou: bool,
) -> dict[str, Any]:
    """Heuristic blast-radius score for operator prioritization."""
    score = 0.0
    score += min(writers, 5) * 1.5
    score += min(link_count, 20) * 0.8
    if linked_to_domain:
        score += 8.0
    if linked_to_root_ou:
        score += 4.0
    if score >= 12:
        tier = "critical"
    elif score >= 7:
        tier = "high"
    elif score >= 3:
        tier = "medium"
    else:
        tier = "low"
    return {"score": round(score, 2), "tier": tier}


@register_capability(
    id="gpo-abuse",
    summary="Enumerate writable GPOs with link-based blast-radius ranking",
    category="privilege-escalation",
    tags=("gpo", "group-policy", "abuse", "acl", "impact"),
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
            "ranked": [],
        }

        # Collect GPO objects
        gpo_by_cn: dict[str, dict[str, Any]] = {}
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
            gpo: dict[str, Any] = {
                "cn": cn,
                "display_name": display,
                "dn": dn,
                "sysvol": str(entry.gPCFileSysPath) if entry.gPCFileSysPath else None,
                "flags": int(entry.flags.value) if entry.flags else None,
                "version": int(entry.versionNumber.value) if entry.versionNumber else None,
                "writers": [],
                "link_count": 0,
                "linked_containers": [],
                "linked_to_domain": False,
                "linked_to_root_ou": False,
            }
            gpo_id = f"GPO@{cn.upper()}@{target.domain.upper()}"
            graph.add_node(
                gpo_id, "GPO", cn=cn, display_name=display, dn=dn, sysvol=gpo["sysvol"]
            )

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

            gpo_by_cn[cn.upper()] = gpo
            result["gpos"].append(gpo)

        # GPLinks on domain + OUs — drive impact scoring
        try:
            conn.search(
                base_dn,
                "(|(objectClass=organizationalUnit)(objectClass=domainDNS))",
                search_scope=SUBTREE,
                attributes=["distinguishedName", "gPLink", "name", "objectClass"],
            )
            for entry in conn.entries:
                gplink = str(entry.gPLink) if entry.gPLink else None
                if not gplink:
                    continue
                container_dn = str(entry.distinguishedName)
                classes = [
                    str(c).lower()
                    for c in (entry.objectClass.values if entry.objectClass else [])
                ]
                is_domain = "domaindns" in classes
                is_rootish = container_dn.upper().count("OU=") <= 1

                link = {
                    "container": container_dn,
                    "name": str(entry.name) if entry.name else None,
                    "is_domain": is_domain,
                    "gplink": gplink[:500],
                }
                result["links"].append(link)

                for match in GUID_RE.finditer(gplink):
                    guid = match.group(1).upper()
                    # GPO cn is typically {GUID}
                    key = f"{{{guid}}}"
                    gpo = gpo_by_cn.get(key) or gpo_by_cn.get(guid)
                    if not gpo:
                        continue
                    gpo["link_count"] += 1
                    gpo["linked_containers"].append(container_dn)
                    if is_domain:
                        gpo["linked_to_domain"] = True
                    if is_rootish:
                        gpo["linked_to_root_ou"] = True
                    graph.add_edge(
                        f"CONTAINER@{container_dn}",
                        f"GPO@{gpo['cn'].upper()}@{target.domain.upper()}",
                        "GPLink",
                    )
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]GPLink enum limited: {exc}[/yellow]")

        # Rank writable GPOs by impact
        ranked: list[dict[str, Any]] = []
        for gpo in result["gpos"]:
            if not gpo["writers"]:
                console.print(f"  GPO  {gpo['display_name']}")
                continue
            impact = _impact_score(
                writers=len(gpo["writers"]),
                link_count=int(gpo["link_count"]),
                linked_to_domain=bool(gpo["linked_to_domain"]),
                linked_to_root_ou=bool(gpo["linked_to_root_ou"]),
            )
            gpo["impact"] = impact
            entry = {
                "cn": gpo["cn"],
                "display_name": gpo["display_name"],
                "writers": gpo["writers"],
                "sysvol": gpo["sysvol"],
                "link_count": gpo["link_count"],
                "linked_to_domain": gpo["linked_to_domain"],
                "impact": impact,
            }
            result["writable_gpos"].append(entry)
            ranked.append(entry)
            console.print(
                f"  [red]Writable GPO[/red]  {gpo['display_name']}  "
                f"writers={len(gpo['writers'])}  links={gpo['link_count']}  "
                f"impact={impact['tier']}({impact['score']})"
            )

        ranked.sort(key=lambda x: (-x["impact"]["score"], -x["link_count"]))
        result["ranked"] = ranked

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
        if ranked:
            top = ranked[0]
            console.print(
                f"  highest impact: [cyan]{top['display_name']}[/cyan]  "
                f"{top['impact']['tier']} ({top['impact']['score']})"
            )
        console.print(f"Results → {out_path}")
        return result
