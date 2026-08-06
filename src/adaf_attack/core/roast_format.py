"""Hashcat / John compatible Kerberos ticket formatting."""

from __future__ import annotations

import struct
from typing import Any


def _bytes_to_hex(data: bytes) -> str:
    return data.hex()


def format_tgs_hashcat(
    tgs: dict[str, Any],
    username: str,
    domain: str,
    spn: str,
) -> str | None:
    """Build a hashcat-mode-13100 ($krb5tgs$23$) line from an Impacket TGS.

    Falls back to None if the ticket structure cannot be parsed.
    """
    try:
        # Impacket TGS structure: tgs['ticket']['enc-part'] contains etype + cipher
        ticket = tgs["ticket"]
        enc_part = ticket["enc-part"]
        etype = enc_part["etype"]
        cipher = enc_part["cipher"]

        if isinstance(cipher, str):
            cipher = bytes.fromhex(cipher) if all(c in "0123456789abcdefABCDEF" for c in cipher) else cipher.encode()

        # checksum = first 16 bytes, data = rest (common for RC4/AES in hashcat format)
        if len(cipher) < 16:
            return None

        checksum = _bytes_to_hex(cipher[:16])
        data = _bytes_to_hex(cipher[16:])

        # hashcat 13100 format
        # $krb5tgs$23$*user$realm$spn*$checksum$data
        return (
            f"$krb5tgs${etype}$*{username}${domain.upper()}${spn}*${checksum}${data}"
        )
    except Exception:  # noqa: BLE001
        return None


def format_asrep_hashcat(
    as_rep: Any,
    username: str,
    domain: str,
) -> str | None:
    """Build a hashcat-mode-18200 ($krb5asrep$23$) line.

    Accepts either a raw dict-like AS-REP or bytes.
    """
    try:
        # Common Impacket path: as_rep['enc-part']['cipher']
        if isinstance(as_rep, dict):
            enc_part = as_rep.get("enc-part") or as_rep.get("encPart")
            if enc_part is None:
                return None
            etype = enc_part.get("etype", 23)
            cipher = enc_part.get("cipher")
        else:
            # best-effort
            etype = 23
            cipher = as_rep

        if isinstance(cipher, str):
            cipher = bytes.fromhex(cipher) if all(c in "0123456789abcdefABCDEF" for c in cipher) else cipher.encode()

        if not isinstance(cipher, (bytes, bytearray)) or len(cipher) < 16:
            return None

        checksum = _bytes_to_hex(cipher[:16])
        data = _bytes_to_hex(cipher[16:])

        return f"$krb5asrep${etype}${username}@{domain.upper()}:{checksum}${data}"
    except Exception:  # noqa: BLE001
        return None
