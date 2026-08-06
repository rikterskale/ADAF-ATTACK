"""Computer-object identity takeover surface discovery."""

from __future__ import annotations

import json
from typing import Any

from ldap3 import SUBTREE

from adaf_attack.core.acl import fetch_sd, parse_interesting_aces
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


@register_capability(
    id="computer-takeover",
    summary="Identify writable computer SPN and DNS identity surfaces",
    category="enumeration",
    tags=("computer", "spn", "dns", "acl"),
)
class ComputerTakeover:
    def run(self, target: Target, session: Session, graph: AttackGraph, **kwargs: Any) -> dict[str, Any]:
        conn, base_dn, _cfg = ldap_connect(target)
        hits: list[dict[str, str]] = []
        conn.search(base_dn, "(objectClass=computer)", search_scope=SUBTREE, attributes=["sAMAccountName", "distinguishedName"], size_limit=int(kwargs.get("max_objects") or 500))
        for entry in conn.entries:
            sam, dn = str(entry.sAMAccountName), str(entry.distinguishedName)
            descriptor = fetch_sd(conn, dn)
            if descriptor:
                for ace in parse_interesting_aces(descriptor):
                    if ace.right in {"GenericAll", "GenericWrite", "WriteProperty", "WriteDacl", "WriteOwner"}:
                        hits.append({"computer": sam, "dn": dn, "principal_sid": ace.principal_sid, "right": ace.right})
                        graph.add_edge(f"SID@{ace.principal_sid}", f"COMPUTER@{sam.upper()}@{target.domain.upper()}", "WriteComputerIdentity", right=ace.right)
        conn.unbind()
        result = {"domain": target.domain, "identity_attributes": ["servicePrincipalName", "dNSHostName", "msDS-AdditionalDnsHostName"], "hits": hits, "count": len(hits)}
        session.path("computer-takeover.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log("computer-takeover.complete", count=len(hits))
        return result
