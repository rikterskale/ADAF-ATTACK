"""Unit tests for KeyCredential blob and RBCD SD builders."""

from adaf_attack.core.keycred import (
    KEY_CREDENTIAL_LINK_VERSION_2,
    build_keycredential_blob,
    generate_shadow_material,
    to_dn_binary,
)


def test_build_keycredential_blob_has_version() -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    blob = build_keycredential_blob(key.public_key().public_numbers())
    assert len(blob) > 20
    # little-endian version 0x200
    assert int.from_bytes(blob[:4], "little") == KEY_CREDENTIAL_LINK_VERSION_2


def test_to_dn_binary_format() -> None:
    s = to_dn_binary(b"\x01\x02", "CN=Test,DC=corp,DC=local")
    assert s.startswith("B:")
    assert "CN=Test,DC=corp,DC=local" in s


def test_generate_shadow_material() -> None:
    mat = generate_shadow_material("alice", "CN=alice,CN=Users,DC=corp,DC=local")
    assert mat["dn_binary"].startswith("B:")
    assert (
        b"BEGIN PRIVATE KEY" in mat["private_key_pem"]
        or b"BEGIN RSA PRIVATE KEY" in mat["private_key_pem"]
    )
    assert b"BEGIN CERTIFICATE" in mat["cert_pem"]
    assert mat["blob_len"] > 0


def test_build_allowed_to_act_sd() -> None:
    try:
        from adaf_attack.core.rbcd_sd import build_allowed_to_act_sd
    except Exception:
        import pytest

        pytest.skip("impacket not available")
    sd = build_allowed_to_act_sd("S-1-5-21-1-2-3-1104")
    assert isinstance(sd, bytes | bytearray)
    assert len(sd) > 16
