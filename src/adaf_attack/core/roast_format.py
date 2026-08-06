"""Helpers to emit hashcat-compatible Kerberos roast hashes."""

from __future__ import annotations

from typing import Any


def _hex(data: bytes) -> str:
    return data.hex()


def format_tgs_hashcat(
    spn: str,
    username: str,
    domain: str,
    ticket: Any,
) -> str | None:
    """Build $krb5tgs$23$... from an Impacket TGS ticket object when possible."""
    try:
        # Impacket KerberosTicket / TGS_REP style
        enc = getattr(ticket, "ticket", ticket)
        if hasattr(enc, "enc-part") or hasattr(enc, "enc_part"):
            enc_part = getattr(enc, "enc-part", None) or getattr(enc, "enc_part", None)
        else:
            enc_part = getattr(ticket, "encPart", None) or getattr(ticket, "enc_part", None)

        cipher = None
        if enc_part is not None:
            cipher = getattr(enc_part, "cipher", None)
            if cipher is None and hasattr(enc_part, "getComponentByName"):
                cipher = enc_part.getComponentByName("cipher")

        if cipher is None:
            return None

        if isinstance(cipher, str):
            if all(c in "0123456789abcdefABCDEF" for c in cipher):
                cipher = bytes.fromhex(cipher)
            else:
                cipher = cipher.encode()

        # checksum = first 16 bytes, data = rest (common for RC4/AES in hashcat format)
        if not isinstance(cipher, (bytes, bytearray)) or len(cipher) < 16:
            return None

        checksum = _hex(cipher[:16])
        data = _hex(cipher[16:])
        user = username.split("@")[0]
        # $krb5tgs$23$*user$DOMAIN$spn*$checksum$data
        return f"$krb5tgs$23$*{user}${domain.upper()}${spn}*${checksum}${data}"
    except Exception:  # noqa: BLE001
        return None


def format_asrep_hashcat(username: str, domain: str, as_rep: Any) -> str | None:
    """Build $krb5asrep$23$... from an AS-REP structure when possible."""
    try:
        enc_part = getattr(as_rep, "encPart", None) or getattr(as_rep, "enc_part", None)
        if enc_part is None and hasattr(as_rep, "getComponentByName"):
            enc_part = as_rep.getComponentByName("enc-part")

        cipher = None
        if enc_part is not None:
            cipher = getattr(enc_part, "cipher", None)
            if cipher is None and hasattr(enc_part, "getComponentByName"):
                cipher = enc_part.getComponentByName("cipher")

        if cipher is None:
            return None

        if isinstance(cipher, str):
            if all(c in "0123456789abcdefABCDEF" for c in cipher):
                cipher = bytes.fromhex(cipher)
            else:
                cipher = cipher.encode()

        if not isinstance(cipher, (bytes, bytearray)) or len(cipher) < 16:
            return None

        checksum = _hex(cipher[:16])
        data = _hex(cipher[16:])
        user = username.split("@")[0]
        return f"$krb5asrep$23${user}@{domain.upper()}:{checksum}${data}"
    except Exception:  # noqa: BLE001
        return None
