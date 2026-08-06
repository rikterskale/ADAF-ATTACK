"""gMSA inventory and LAPS attribute presence / read-right signals."""

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

GMSA_FILTER = "(objectClass=msDS-GroupManagedServiceAccount)"
GMSA_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "objectSid",
    "msDS-ManagedPasswordInterval",
    "msDS-GroupMSAMembership",
    "servicePrincipalName",
    "userAccountControl",
]

# Computers that may hold LAPS passwords
LAPS_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "ms-Mcs-AdmPwd",
    "ms-Mcs-AdmPwdExpirationTime",
    "msLAPS-Password",
    "msLAPS-PasswordExpirationTime",
    "msLAPS-EncryptedPassword",
]


@register_capability(
    id="gmsa-laps-enum",
    summary="Enumerate gMSAs and LAPS-enabled computers; flag readable password attributes",
    category="enumeration",
    tags=("gmsa", "laps", "credentials"),
)
class GmsaLapsEnum:
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
        console.print(f"[bold]gMSA / LAPS enum[/bold] → {target.domain} @ {target.dc_ip}")
        conn, base_dn, _cfg = ldap_connect(target)

        gmsas: list[dict[str, Any]] = []
        conn.search(base_dn, GMSA_FILTER, search_scope=SUBTREE, attributes=GMSA_ATTRS)
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not sam:
                continue
            dn = str(entry.distinguishedName)
            item = {
                "sam": sam,
                "dn": dn,
                "interval": int(entry["msDS-ManagedPasswordInterval"].value)
                if entry["msDS-ManagedPasswordInterval"]
                else None,
                "spns": [str(s) for s in (entry.servicePrincipalName or [])],
            }
            # Who is allowed to retrieve managed password (group MSA membership)
            membership = entry["msDS-GroupMSAMembership"]
            if membership:
                item["group_msa_membership_raw"] = str(membership.value)[:200]

            # SD-based ReadProperty signal (does not dump the secret)
            readable_by: list[str] = []
            sd = fetch_sd(conn, dn)
            if sd:
                try:
                    for ace in parse_interesting_aces(sd):
                        if ace.right in ("GenericAll", "ReadProperty", "GenericWrite"):
                            readable_by.append(f"{ace.principal_sid}:{ace.right}")
                except Exception:  # noqa: BLE001
                    pass
            item["acl_read_signals"] = readable_by[:20]

            node_id = f"GMSA@{sam.upper()}@{target.domain.upper()}"
            graph.add_node(node_id, "User", sam=sam, dn=dn, gmsa=True)
            if readable_by:
                graph.add_edge(node_id, node_id, "GMSAPasswordReadable")
            gmsas.append(item)
            console.print(f"  gMSA [cyan]{sam}[/cyan]  acl_signals={len(readable_by)}")

        # LAPS — presence of password attributes (values redacted always)
        laps_computers: list[dict[str, Any]] = []
        conn.search(
            base_dn,
            "(&(objectCategory=computer)(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*)))",
            search_scope=SUBTREE,
            attributes=LAPS_ATTRS,
        )
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not sam:
                continue
            dn = str(entry.distinguishedName)
            legacy = bool(entry["ms-Mcs-AdmPwd"])
            win_laps = bool(entry["msLAPS-Password"] or entry["msLAPS-EncryptedPassword"])
            item = {
                "sam": sam,
                "dn": dn,
                "legacy_laps": legacy,
                "windows_laps": win_laps,
                # never export password values
                "password_present": legacy or win_laps,
            }

            readable_by = []
            sd = fetch_sd(conn, dn)
            if sd:
                try:
                    for ace in parse_interesting_aces(sd):
                        if ace.right in ("GenericAll", "ReadProperty"):
                            readable_by.append(f"{ace.principal_sid}:{ace.right}")
                except Exception:  # noqa: BLE001
                    pass
            item["acl_read_signals"] = readable_by[:20]

            node_id = f"COMPUTER@{sam.upper()}@{target.domain.upper()}"
            graph.add_node(
                node_id,
                "Computer",
                sam=sam,
                dn=dn,
                laps=True,
                legacy_laps=legacy,
                windows_laps=win_laps,
            )
            if readable_by:
                graph.add_edge(node_id, node_id, "LAPSReadable")
            laps_computers.append(item)
            console.print(
                f"  LAPS [cyan]{sam}[/cyan]  legacy={legacy} windows={win_laps} "
                f"acl_signals={len(readable_by)}"
            )

        conn.unbind()

        result = {
            "domain": target.domain,
            "gmsa_count": len(gmsas),
            "gmsas": gmsas,
            "laps_computer_count": len(laps_computers),
            "laps_computers": laps_computers,
        }

        out_path = session.path("gmsa-laps-enum.json")
        out_path.write_text(json.dumps(result, indent=2, default=str))
        graph.save(session.path("graph.json"))
        session.log(
            "gmsa-laps-enum.complete",
            gmsa=len(gmsas),
            laps=len(laps_computers),
        )

        console.print(
            f"[green]Done[/green]  gMSA={len(gmsas)}  LAPS-computers={len(laps_computers)}"
        )
        console.print(
            "[dim]Password values are never written. ACL signals indicate possible readers, not confirmed dump rights.[/dim]"
        )
        console.print(f"Results → {out_path}")
        return result
