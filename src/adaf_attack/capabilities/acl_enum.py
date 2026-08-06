"""ACL enumeration — interesting permission edges on high-value objects."""

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

# Builtin SIDs we still record but mark as low signal
NOISY_SIDS = {
    "S-1-5-10",  # Principal Self
    "S-1-5-18",  # Local System
    "S-1-3-0",  # Creator Owner
    "S-1-5-11",  # Authenticated Users — still interesting on some objects
    "S-1-1-0",  # Everyone
}


def _sid_index(conn: Any, base_dn: str) -> dict[str, dict[str, str]]:
    """Map SID → {sam, type, dn}."""
    index: dict[str, dict[str, str]] = {}
    conn.search(
        base_dn,
        "(|(objectClass=user)(objectClass=group)(objectClass=computer))",
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "objectSid", "objectClass", "distinguishedName"],
    )
    for entry in conn.entries:
        if not entry.objectSid:
            continue
        try:
            sid = entry.objectSid.value
            if hasattr(sid, "formatCanonical"):
                sid_str = sid.formatCanonical()
            else:
                sid_str = str(sid)
        except Exception:  # noqa: BLE001
            continue
        classes = [str(c).lower() for c in (entry.objectClass.values if entry.objectClass else [])]
        if "computer" in classes:
            kind = "Computer"
        elif "group" in classes:
            kind = "Group"
        else:
            kind = "User"
        sam = str(entry.sAMAccountName) if entry.sAMAccountName else sid_str
        index[sid_str] = {
            "sam": sam,
            "kind": kind,
            "dn": str(entry.distinguishedName),
        }
    return index


def _domain_targets(
    conn: Any, base_dn: str, domain: str, *, limit: int = 500
) -> list[tuple[str, str, str]]:
    """Broader crawl: domain root + AdminSDHolder + users/groups/computers up to limit."""
    targets = _high_value_targets(conn, base_dn, domain)
    seen = {t[1].lower() for t in targets}

    conn.search(
        base_dn,
        "(|(objectClass=user)(objectClass=group)(objectClass=computer))",
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "distinguishedName", "objectClass"],
        size_limit=limit,
    )
    for entry in conn.entries:
        if len(targets) >= limit:
            break
        sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
        dn = str(entry.distinguishedName)
        if not sam or dn.lower() in seen:
            continue
        seen.add(dn.lower())
        classes = [str(c).lower() for c in (entry.objectClass.values if entry.objectClass else [])]
        if "computer" in classes:
            node_id = f"COMPUTER@{sam.upper()}@{domain.upper()}"
            label = "Computer"
        elif "group" in classes:
            node_id = f"GROUP@{sam.upper()}@{domain.upper()}"
            label = "Group"
        else:
            node_id = f"USER@{sam.upper()}@{domain.upper()}"
            label = "User"
        targets.append((node_id, dn, label))
    return targets


def _high_value_targets(conn: Any, base_dn: str, domain: str) -> list[tuple[str, str, str]]:
    """Return list of (node_id, dn, label) for domain root + privileged groups + adminCount."""
    targets: list[tuple[str, str, str]] = []
    domain_id = f"DOMAIN@{domain.upper()}"
    targets.append((domain_id, base_dn, "Domain"))

    # AdminSDHolder
    asd = f"CN=AdminSDHolder,CN=System,{base_dn}"
    targets.append((f"ADMINSDHOLDER@{domain.upper()}", asd, "AdminSDHolder"))

    conn.search(
        base_dn,
        "(|(adminCount=1)(sAMAccountName=Domain Admins)(sAMAccountName=Enterprise Admins))",
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "distinguishedName", "objectClass"],
    )
    for entry in conn.entries:
        sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
        dn = str(entry.distinguishedName)
        if not sam:
            continue
        classes = [str(c).lower() for c in (entry.objectClass.values if entry.objectClass else [])]
        if "group" in classes:
            node_id = f"GROUP@{sam.upper()}@{domain.upper()}"
            targets.append((node_id, dn, "Group"))
        elif "computer" in classes:
            node_id = f"COMPUTER@{sam.upper()}@{domain.upper()}"
            targets.append((node_id, dn, "Computer"))
        else:
            node_id = f"USER@{sam.upper()}@{domain.upper()}"
            targets.append((node_id, dn, "User"))

    # de-dupe by dn
    seen: set[str] = set()
    out = []
    for t in targets:
        if t[1].lower() in seen:
            continue
        seen.add(t[1].lower())
        out.append(t)
    return out


@register_capability(
    id="acl-enum",
    summary="Enumerate interesting ACL edges (high-value or domain-wide scope)",
    category="enumeration",
    tags=("acl", "dacl", "genericall", "writedacl", "dcsync"),
)
class AclEnum:
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
        # scope: high-value (default) | domain
        # max_objects: hard cap for domain-wide crawl (default 500)
        scope = str(kwargs.get("scope") or "high-value").lower()
        max_objects = int(kwargs.get("max_objects") or 500)

        console.print(f"[bold]ACL enum[/bold] → {target.domain} @ {target.dc_ip}  scope={scope}")

        conn, base_dn, _cfg = ldap_connect(target)
        domain_id = f"DOMAIN@{target.domain.upper()}"
        graph.add_node(domain_id, "Domain", name=target.domain, dn=base_dn)

        console.print("[dim]Building SID index…[/dim]")
        sid_map = _sid_index(conn, base_dn)
        console.print(f"  Indexed {len(sid_map)} principals")

        # Pre-create graph nodes for principals
        for sid, info in sid_map.items():
            if info["kind"] == "Group":
                nid = f"GROUP@{info['sam'].upper()}@{target.domain.upper()}"
            elif info["kind"] == "Computer":
                nid = f"COMPUTER@{info['sam'].upper()}@{target.domain.upper()}"
            else:
                nid = f"USER@{info['sam'].upper()}@{target.domain.upper()}"
            graph.add_node(nid, info["kind"], sam=info["sam"], dn=info["dn"], sid=sid)

        if scope in ("domain", "full", "all"):
            hv = _domain_targets(conn, base_dn, target.domain, limit=max_objects)
            console.print(
                f"Scanning DACLs domain-wide on up to {len(hv)} objects "
                f"(max_objects={max_objects})…"
            )
        else:
            hv = _high_value_targets(conn, base_dn, target.domain)
            console.print(f"Scanning DACLs on {len(hv)} high-value objects…")

        edges_out: list[dict[str, Any]] = []
        dcsync_principals: set[str] = set()

        for node_id, dn, label in hv:
            graph.add_node(node_id, label if label != "AdminSDHolder" else "Container", dn=dn)
            sd = fetch_sd(conn, dn)
            if not sd:
                continue
            try:
                aces = parse_interesting_aces(sd)
            except RuntimeError as exc:
                conn.unbind()
                raise exc
            except Exception as exc:  # noqa: BLE001
                console.print(f"  [yellow]parse fail {dn}: {exc}[/yellow]")
                continue

            for ace in aces:
                if ace.right == "ReadProperty":
                    continue  # too noisy without attribute targeting
                principal = sid_map.get(ace.principal_sid)
                if principal:
                    src_id = {
                        "Group": f"GROUP@{principal['sam'].upper()}@{target.domain.upper()}",
                        "Computer": f"COMPUTER@{principal['sam'].upper()}@{target.domain.upper()}",
                        "User": f"USER@{principal['sam'].upper()}@{target.domain.upper()}",
                    }[principal["kind"]]
                    src_label = principal["sam"]
                else:
                    src_id = f"SID@{ace.principal_sid}"
                    graph.add_node(src_id, "Base", sid=ace.principal_sid)
                    src_label = ace.principal_sid

                # DCSync = GetChanges + GetChangesAll on domain
                if ace.right in ("GetChanges", "GetChangesAll") and label == "Domain":
                    dcsync_principals.add(src_id)

                graph.add_edge(
                    src_id,
                    node_id,
                    ace.right,
                    principal_sid=ace.principal_sid,
                    target_dn=dn,
                )
                edges_out.append(
                    {
                        "source": src_label,
                        "source_id": src_id,
                        "right": ace.right,
                        "target": node_id,
                        "target_dn": dn,
                        "noisy": ace.principal_sid in NOISY_SIDS
                        or ace.principal_sid.startswith("S-1-5-11")
                        or ace.principal_sid.startswith("S-1-1-0"),
                    }
                )

        # Mark DCSync-capable principals (both rights)
        get_changes = {e["source_id"] for e in edges_out if e["right"] == "GetChanges"}
        get_all = {e["source_id"] for e in edges_out if e["right"] == "GetChangesAll"}
        dcsync = sorted(get_changes & get_all)
        for src in dcsync:
            graph.add_edge(src, domain_id, "DCSync")

        conn.unbind()

        interesting = [
            e
            for e in edges_out
            if not e["noisy"]
            and e["right"]
            in {
                "GenericAll",
                "WriteDacl",
                "WriteOwner",
                "GenericWrite",
                "ForceChangePassword",
                "GetChangesAll",
                "GetChanges",
                "AllExtendedRights",
            }
        ]

        result = {
            "domain": target.domain,
            "scope": scope,
            "objects_scanned": len(hv),
            "edges": edges_out,
            "interesting_edge_count": len(interesting),
            "dcsync_principals": dcsync,
        }

        out_path = session.path("acl-enum.json")
        out_path.write_text(json.dumps(result, indent=2, default=str))
        graph.save(session.path("graph.json"))
        session.log("acl-enum.complete", edges=len(edges_out), dcsync=len(dcsync))

        console.print(
            f"[green]Done[/green]  edges={len(edges_out)}  "
            f"interesting={len(interesting)}  dcsync={len(dcsync)}"
        )
        for e in interesting[:15]:
            console.print(f"  [cyan]{e['source']}[/cyan] -{e['right']}→ {e['target']}")
        if len(interesting) > 15:
            console.print(f"  … {len(interesting) - 15} more")
        console.print(f"Results → {out_path}")
        return result
