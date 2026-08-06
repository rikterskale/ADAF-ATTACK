"""Helpers to emit hashcat-compatible Kerberos roast hashes."""

from __future__ import annotations

from typing import Any


def _hex(data: bytes) -> str:
    return data.hex()


def _extract_cipher_and_etype(ticket: Any) -> tuple[bytes | None, int | None]:
    """Best-effort extract of encrypted part + etype from Impacket ticket objects."""
    etype = None
    cipher = None

    try:
        # TGS_REP / AS_REP pyasn1 style
        if hasattr(ticket, "getComponentByName"):
            enc = ticket.getComponentByName("enc-part") or ticket.getComponentByName("ticket")
            if enc is not None and hasattr(enc, "getComponentByName"):
                # may be nested ticket.enc-part
                inner = enc.getComponentByName("enc-part") or enc
                if hasattr(inner, "getComponentByName"):
                    etype_c = inner.getComponentByName("etype")
                    cipher_c = inner.getComponentByName("cipher")
                    if etype_c is not None:
                        etype = int(etype_c)
                    if cipher_c is not None:
                        cipher = bytes(cipher_c)
        enc_part = getattr(ticket, "encPart", None) or getattr(ticket, "enc_part", None)
        if enc_part is not None and cipher is None:
            cipher = getattr(enc_part, "cipher", None)
            etype = getattr(enc_part, "etype", etype)
            if cipher is None and hasattr(enc_part, "getComponentByName"):
                cipher = enc_part.getComponentByName("cipher")
                etype_c = enc_part.getComponentByName("etype")
                if etype_c is not None:
                    etype = int(etype_c)
        if isinstance(cipher, str):
            if all(c in "0123456789abcdefABCDEF" for c in cipher):
                cipher = bytes.fromhex(cipher)
            else:
                cipher = cipher.encode()
        if cipher is not None and not isinstance(cipher, bytes | bytearray):
            cipher = bytes(cipher)
    except Exception:  # noqa: BLE001
        return None, None
    return cipher, etype


def format_tgs_hashcat(
    spn: str,
    username: str,
    domain: str,
    ticket: Any,
) -> str | None:
    """Build $krb5tgs$<etype>$... from an Impacket TGS ticket when possible.

    RC4 (23) → hashcat 13100 style
    AES128 (17) / AES256 (18) → hashcat 19600/19700 style fields
    """
    try:
        cipher, etype = _extract_cipher_and_etype(ticket)
        if cipher is None or len(cipher) < 16:
            return None
        user = username.split("@")[0]
        etype = etype or 23
        if etype in (17, 18):
            # AES: checksum is last 12 bytes for hashcat krb5tgs aes formats
            checksum = _hex(cipher[-12:])
            data = _hex(cipher[:-12])
            return f"$krb5tgs${etype}$*{user}${domain.upper()}${spn}*${checksum}${data}"
        # RC4 default
        checksum = _hex(cipher[:16])
        data = _hex(cipher[16:])
        return f"$krb5tgs$23$*{user}${domain.upper()}${spn}*${checksum}${data}"
    except Exception:  # noqa: BLE001
        return None


def format_asrep_hashcat(username: str, domain: str, as_rep: Any) -> str | None:
    """Build $krb5asrep$<etype>$... from an AS-REP structure when possible."""
    try:
        cipher, etype = _extract_cipher_and_etype(as_rep)
        if cipher is None or len(cipher) < 16:
            return None
        user = username.split("@")[0]
        etype = etype or 23
        checksum = _hex(cipher[:16])
        data = _hex(cipher[16:])
        return f"$krb5asrep${etype}${user}@{domain.upper()}:{checksum}${data}"
    except Exception:  # noqa: BLE001
        return None
