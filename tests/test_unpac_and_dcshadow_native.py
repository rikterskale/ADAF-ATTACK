"""Native UnPAC decryption helpers and DCShadow DRSAddEntry wiring."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from adaf_attack.capabilities import adcs_esc, relay_ops, unpac_the_hash, workflow_wrappers
from adaf_attack.core import drs_addentry, unpac
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def _target(**kwargs: Any) -> Target:
    values = {
        "domain": "corp.test",
        "dc_ip": "10.0.0.1",
        "username": "alice",
        "password": "Secret1!",
    }
    values.update(kwargs)
    return Target(**values)


def test_parse_asrep_and_nt_hash_from_tool_output() -> None:
    text = (
        "AS-REP encryption key: aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\n"
    )
    assert unpac.parse_asrep_key(text) == (
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    )
    nt_text = "[*] Got NT hash for alice@corp.test: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
    assert unpac.parse_nt_hash_from_text(nt_text) == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_attr_oid_resolution() -> None:
    assert drs_addentry._attr_oid("description") == "2.5.4.13"
    assert drs_addentry._attr_oid("2.5.4.13") == "2.5.4.13"
    with pytest.raises(RuntimeError, match="Unknown attribute"):
        drs_addentry._attr_oid("not-a-real-attr")


def test_unpac_recovers_from_certipy_stdout(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setattr(unpac_the_hash, "require_impacket", lambda name: None)

    class Pkinit:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {
                "ccache": str(tmp_path / "alice.ccache"),
                "stdout": (
                    "[*] Got NT hash for alice@corp.test: "
                    "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
                ),
            }

    monkeypatch.setitem(
        __import__("sys").modules,
        "adaf_attack.capabilities.pkinit_auth",
        SimpleNamespace(PkinitAuth=Pkinit),
    )
    # Import path uses from-import inside run; patch the class on the module object.
    import adaf_attack.capabilities.pkinit_auth as pkinit_mod

    monkeypatch.setattr(pkinit_mod, "PkinitAuth", Pkinit)

    result = unpac_the_hash.UnpacTheHash().run(
        _target(),
        Session(tmp_path),
        AttackGraph(),
        sam="alice",
        pfx="cert.pfx",
        include_secrets=True,
    )
    assert result["ok"] is True
    assert result["status"] == "recovered"
    assert result["nt_hash"] == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert result["pac_credential_info"]["method"] == "certipy-auth"


def test_unpac_uses_u2u_when_asrep_key_present(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setattr(unpac_the_hash, "require_impacket", lambda name: None)

    class Pkinit:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ccache": str(tmp_path / "alice.ccache"), "asrep_key": "aa" * 32}

    import adaf_attack.capabilities.pkinit_auth as pkinit_mod

    monkeypatch.setattr(pkinit_mod, "PkinitAuth", Pkinit)
    monkeypatch.setattr(
        unpac_the_hash,
        "request_u2u_pac",
        lambda **kwargs: {
            "ok": True,
            "nt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "lm_hash": "aad3b435b51404eeaad3b435b51404ee",
        },
    )
    result = unpac_the_hash.UnpacTheHash().run(
        _target(), Session(tmp_path), AttackGraph(), sam="alice", pfx="cert.pfx"
    )
    assert result["ok"] is True
    assert result["pac_credential_info"]["method"] == "u2u-pac"
    assert result["nt_hash_present"] is True


def test_dcshadow_performs_push_when_attrs_supplied(monkeypatch: Any, tmp_path: Path) -> None:
    class Attr:
        def __init__(self, value: Any = None) -> None:
            self.value = value
            self.values = value if isinstance(value, list) else ([] if value is None else [value])
            self.raw_values = self.values

    class Entry:
        def __init__(self, **values: Any) -> None:
            self._values = {k: Attr(v) for k, v in values.items()}

        def __getattr__(self, name: str) -> Attr:
            return self._values.get(name, Attr())

    class Conn:
        def __init__(self) -> None:
            self.entries: list[Any] = []
            self.result = {"result": 0}
            self.modifies: list[Any] = []
            self.adds: list[Any] = []

        def search(self, *args: Any, **kwargs: Any) -> bool:
            self.entries = [
                Entry(
                    sAMAccountName="ROGUE$",
                    distinguishedName="CN=ROGUE,DC=corp,DC=test",
                    dNSHostName="rogue.corp.test",
                    servicePrincipalName=[],
                )
            ]
            return True

        def add(self, *args: Any, **kwargs: Any) -> bool:
            self.adds.append(args)
            return True

        def modify(self, dn: str, changes: Any) -> bool:
            self.modifies.append((dn, changes))
            return True

        def unbind(self) -> None:
            return None

    conn = Conn()
    monkeypatch.setattr(
        relay_ops,
        "ldap_connect",
        lambda t: (conn, "DC=corp,DC=test", "CN=Configuration,DC=corp,DC=test"),
    )
    monkeypatch.setattr(
        "adaf_attack.core.drs_addentry.add_entry_modify",
        lambda *a, **k: {"ok": True, "method": "drsuapi", "error_code": 0},
    )
    result = relay_ops.DcShadow().run(
        _target(),
        Session(tmp_path),
        AttackGraph(),
        force=True,
        computer="ROGUE$",
        object="CN=Alice,DC=corp,DC=test",
        attribute="description",
        value="pushed",
    )
    assert result["replication_push"]["performed"] is True
    assert result["status"] == "pushed"
    assert conn.modifies  # SPNs registered


def test_golden_cert_native_forge_fallback(monkeypatch: Any, tmp_path: Path) -> None:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca_pfx = tmp_path / "ca.pfx"
    ca_pfx.write_bytes(
        pkcs12.serialize_key_and_certificates(
            name=b"ca",
            key=key,
            cert=ca_cert,
            cas=None,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    monkeypatch.setattr(
        adcs_esc,
        "_run_certipy",
        lambda *a, **k: {"ok": False, "method": "playbook-only", "playbook": "x"},
    )
    session = Session(tmp_path / "sess")
    result = adcs_esc.GoldenCert().run(
        _target(),
        session,
        AttackGraph(),
        force=True,
        ca_pfx=str(ca_pfx),
        upn="administrator@corp.test",
    )
    assert result["ok"] is True
    assert result["method"] == "native-forge"
    assert Path(result["pfx"]).is_file()


def test_controlled_computer_target_helper() -> None:
    base = _target(username="CONTROL$", password="x")
    built = workflow_wrappers._controlled_computer_target(base, "CONTROL$", {})
    assert built is not None and built.username == "CONTROL$"
    assert workflow_wrappers._controlled_computer_target(base, "OTHER$", {}) is None
    with_pass = workflow_wrappers._controlled_computer_target(
        base, "OTHER$", {"computer_password": "y"}
    )
    assert with_pass is not None and with_pass.password == "y"


def test_parse_helpers_handle_empty_input() -> None:
    assert unpac.parse_asrep_key(None) is None
    assert unpac.parse_asrep_key("no key here") is None
    assert unpac.parse_nt_hash_from_text(None) is None
    assert unpac.parse_nt_hash_from_text("nothing") is None


def test_attr_oid_rejects_empty_and_accepts_aliases() -> None:
    with pytest.raises(RuntimeError, match="non-empty"):
        drs_addentry._attr_oid("  ")
    assert drs_addentry._attr_oid("primaryGroupID") == "1.2.840.113556.1.4.98"
    assert drs_addentry._attr_oid("service-principal-name") == "1.2.840.113556.1.4.415"


def test_request_u2u_pac_handles_load_failure(monkeypatch: Any, tmp_path: Path) -> None:
    ccache_path = tmp_path / "broken.ccache"
    ccache_path.write_bytes(b"not-a-ccache")

    class BoomCache:
        @classmethod
        def loadFile(cls, path: str) -> BoomCache:  # noqa: N802
            raise OSError("cannot load")

    import impacket.krb5.ccache as ccache_mod

    monkeypatch.setattr(ccache_mod, "CCache", BoomCache)
    result = unpac.request_u2u_pac(
        ccache_path=str(ccache_path),
        username="alice",
        domain="corp.test",
        dc_ip="10.0.0.1",
        asrep_key_hex="aa" * 32,
    )
    assert result["ok"] is False
    assert "cannot load" in result["error"]


def test_add_entry_modify_connect_error(monkeypatch: Any) -> None:
    monkeypatch.setattr(drs_addentry, "require_impacket", lambda *_a, **_k: None)

    class BoomTransport:
        def __init__(self, *a: Any, **k: Any) -> None:
            pass

        def set_credentials(self, *a: Any, **k: Any) -> None:
            return None

        def get_dce_rpc(self) -> Any:
            raise ConnectionError("access denied to pipe")

    import impacket.dcerpc.v5.transport as transport_mod

    class Req:
        def __setitem__(self, key: str, value: Any) -> None:
            return None

        def __getitem__(self, key: str) -> Any:
            return self

    monkeypatch.setattr(drs_addentry, "_structures", lambda: (Req, Req))
    monkeypatch.setattr(transport_mod, "SMBTransport", BoomTransport)
    result = drs_addentry.add_entry_modify(
        _target(),
        object_dn="CN=Alice,DC=corp,DC=test",
        attribute="description",
        value="x",
    )
    assert result["ok"] is False
    assert "access denied" in result["error"].lower()


def test_drs_structures_build_once() -> None:
    # Reset cache so this exercises the builder path.
    drs_addentry._STRUCTURES = None
    req_cls, resp_cls = drs_addentry._structures()
    again = drs_addentry._structures()
    assert again[0] is req_cls
    assert again[1] is resp_cls
    assert getattr(req_cls, "opnum", None) == drs_addentry.OPNUM_DRS_ADD_ENTRY


def test_build_dsname_sets_length() -> None:
    dsname = drs_addentry._build_dsname("CN=Alice,DC=corp,DC=test")
    assert int(dsname["NameLen"]) == len("CN=Alice,DC=corp,DC=test")


def test_der_utf8_string_short_and_long() -> None:
    short = adcs_esc._der_utf8_string("a")
    assert short.startswith(b"\x0c")
    long_upn = "u" * 200 + "@corp.test"
    long = adcs_esc._der_utf8_string(long_upn)
    assert long[0] == 0x0C
    assert long[1] & 0x80
