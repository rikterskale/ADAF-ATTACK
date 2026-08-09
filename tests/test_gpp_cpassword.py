"""GPP cpassword decrypt + file walker tests."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from adaf_attack.core.gpp import (
    GPP_IV,
    GPP_KEY,
    decrypt_cpassword,
    iter_gpp_files,
    parse_gpp_file,
)


def _encrypt_gpp(plaintext: str) -> str:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    data = plaintext.encode("utf-16-le")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(GPP_KEY), modes.CBC(GPP_IV))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(encrypted).decode("ascii")


def test_decrypt_roundtrip() -> None:
    encoded = _encrypt_gpp("Super$ecret!")
    assert decrypt_cpassword(encoded) == "Super$ecret!"


def test_decrypt_missing_padding_recovers() -> None:
    encoded = _encrypt_gpp("SprayMe1!").rstrip("=")
    assert decrypt_cpassword(encoded) == "SprayMe1!"


def test_decrypt_empty_raises() -> None:
    with pytest.raises(ValueError):
        decrypt_cpassword("")


def test_iter_and_parse_walks_only_expected_names(tmp_path: Path) -> None:
    encoded = _encrypt_gpp("P@ssw0rd!")
    xml = f'<Group><User cpassword="{encoded}" userName="svc-backup"/></Group>'
    (tmp_path / "Ignored.xml").write_text("<foo/>", encoding="utf-8")
    (tmp_path / "Groups.xml").write_text(xml, encoding="utf-8")

    files = list(iter_gpp_files(tmp_path))
    assert len(files) == 1 and files[0].name == "Groups.xml"

    records = parse_gpp_file(files[0])
    assert len(records) == 1
    assert records[0]["plaintext"] == "P@ssw0rd!"
    assert records[0]["username"] == "svc-backup"
