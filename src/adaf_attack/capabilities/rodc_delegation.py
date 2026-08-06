"""Read-only RODC and delegation surface discovery."""

from __future__ import annotations

import json
from typing import Any

from ldap3 import SUBTREE

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


@register_capability(id="rodc-delegation", summary="Enumerate RODC password-replication and delegation exposure", category="enumeration", tags=("rodc", "delegation", "krbtgt"))
class RodcDelegation:
    def run(self, target: Target, session: Session, graph: AttackGraph, **kwargs: Any) -> dict[str, Any]:
        conn, base_dn, _cfg = ldap_connect(target)
        result: dict[str, Any] = {"rodc_accounts": [], "delegation": []}
        conn.search(base_dn, "(&(objectClass=user)(sAMAccountName=krbtgt_*))", search_scope=SUBTREE, attributes=["sAMAccountName", "distinguishedName"])
        for entry in conn.entries:
            result["rodc_accounts"].append({"sam": str(entry.sAMAccountName), "dn": str(entry.distinguishedName)})
        conn.search(base_dn, "(|(objectClass=user)(objectClass=computer))", search_scope=SUBTREE, attributes=["sAMAccountName", "userAccountControl", "msDS-AllowedToDelegateTo"])
        for entry in conn.entries:
            uac = int(entry.userAccountControl.value) if entry.userAccountControl else 0
            constrained = [str(x) for x in (entry["msDS-AllowedToDelegateTo"].value or [])] if entry["msDS-AllowedToDelegateTo"] else []
            if uac & 0x80000 or constrained:
                item = {"account": str(entry.sAMAccountName), "unconstrained": bool(uac & 0x80000), "constrained": constrained}
                result["delegation"].append(item)
                graph.add_edge(f"ACCOUNT@{item['account'].upper()}@{target.domain.upper()}", f"DOMAIN@{target.domain.upper()}", "UnconstrainedDelegation" if item["unconstrained"] else "AllowedToDelegate")
        conn.unbind()
        result["count"] = len(result["rodc_accounts"]) + len(result["delegation"])
        session.path("rodc-delegation.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log("rodc-delegation.complete", count=result["count"])
        return result
