"""Shadow artifact discovery helpers."""

from pathlib import Path

from adaf_attack.capabilities.pkinit_auth import _find_shadow_artifacts, _pfx_from_pem
from adaf_attack.core.session import Session


def test_find_shadow_artifacts(tmp_path: Path) -> None:
    sess = Session(base_dir=tmp_path)
    # minimal fake pem files
    sess.path("shadow-alice.key.pem").write_text("KEY")
    sess.path("shadow-alice.cert.pem").write_text("CERT")
    found = _find_shadow_artifacts(sess, "alice")
    assert found["key"] is not None
    assert found["cert"] is not None


def test_pfx_from_pem_roundtrip() -> None:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")]))
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    pfx = _pfx_from_pem(key_pem, cert_pem)
    assert isinstance(pfx, bytes | bytearray)
    assert len(pfx) > 50
