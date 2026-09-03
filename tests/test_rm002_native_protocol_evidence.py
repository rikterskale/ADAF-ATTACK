"""Behavioral evidence for RM-002 native protocol and adapter paths."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from adaf_attack.capabilities import adcs_esc, esc_chain, impacket_exec, pkinit_auth
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


class _Node(dict[Any, Any]):
    """Small dict-like stand-in for nested ASN.1/NDR values."""

    def __getitem__(self, key: Any) -> Any:
        if key not in self:
            self[key] = _Node()
        return super().__getitem__(key)


def test_decrypt_pac_credential_info_recovers_ntlm_material(monkeypatch: Any) -> None:
    import impacket.dcerpc.v5.rpcrt as rpcrt
    import impacket.krb5.crypto as crypto
    import impacket.krb5.pac as pac

    class Cipher:
        def decrypt(self, key: Any, usage: int, ciphertext: bytes) -> bytes:
            assert key == (23, bytes.fromhex("aa" * 16))
            assert usage == 16
            assert ciphertext == b"encrypted"
            return b"header--payload"

    class PacInfo:
        def __init__(self, _buffer: bytes) -> None:
            self.values = {"Offset": 8, "cbBufferSize": 9, "ulType": 2}

        def __getitem__(self, key: str) -> Any:
            return self.values[key]

        def __len__(self) -> int:
            return 1

    class Pac:
        def __init__(self, _data: bytes) -> None:
            self.values = {"Buffers": b"credential", "cBuffers": 1}

        def __getitem__(self, key: str) -> Any:
            return self.values[key]

    class CredentialInfo:
        def __init__(self, _data: bytes) -> None:
            self.values = {"EncryptionType": 23, "SerializedData": b"encrypted"}

        def __getitem__(self, key: str) -> Any:
            return self.values[key]

    class TypeSerialization:
        def __init__(self, _plain: bytes) -> None:
            pass

        def __len__(self) -> int:
            return 4

    class CredentialData:
        def __init__(self, data: bytes) -> None:
            assert data == b"payload"

        def __getitem__(self, key: str) -> Any:
            assert key == "Credentials"
            return [{"Credentials": [b"ntlm", b"credential"]}]

    class NtlmCredential:
        def __init__(self, data: bytes) -> None:
            assert data == b"ntlmcredential"

        def __getitem__(self, key: str) -> bytes:
            return {"NtPassword": b"\x11" * 16, "LmPassword": b"\x22" * 16}[key]

    monkeypatch.setattr(rpcrt, "TypeSerialization1", TypeSerialization)
    monkeypatch.setattr(crypto, "Key", lambda enctype, key: (enctype, key))
    monkeypatch.setattr(crypto, "_enctype_table", {23: Cipher()})
    monkeypatch.setattr(pac, "PAC_INFO_BUFFER", PacInfo)
    monkeypatch.setattr(pac, "PACTYPE", Pac)
    monkeypatch.setattr(pac, "PAC_CREDENTIAL_INFO", CredentialInfo)
    monkeypatch.setattr(pac, "PAC_CREDENTIAL_DATA", CredentialData)
    monkeypatch.setattr(pac, "NTLM_SUPPLEMENTAL_CREDENTIAL", NtlmCredential)

    result = unpac.decrypt_pac_credential_info(b"pac", "AA" * 16)

    assert result == {
        "status": "recovered",
        "nt_hash": "11" * 16,
        "lm_hash": "22" * 16,
    }


def test_decrypt_pac_credential_info_ignores_non_credential_buffers(monkeypatch: Any) -> None:
    import impacket.krb5.pac as pac

    class PacInfo:
        def __init__(self, _buffer: bytes) -> None:
            self.values = {"Offset": 8, "cbBufferSize": 4, "ulType": 1}

        def __getitem__(self, key: str) -> Any:
            return self.values[key]

        def __len__(self) -> int:
            return 1

    class Pac:
        def __init__(self, _data: bytes) -> None:
            pass

        def __getitem__(self, key: str) -> Any:
            return {"Buffers": b"other", "cBuffers": 1}[key]

    monkeypatch.setattr(pac, "PAC_INFO_BUFFER", PacInfo)
    monkeypatch.setattr(pac, "PACTYPE", Pac)

    assert unpac.decrypt_pac_credential_info(b"pac", "AA" * 16) is None


def test_request_u2u_pac_reports_missing_tgt_and_restores_environment(
    monkeypatch: Any, tmp_path: Path
) -> None:
    import impacket.krb5.ccache as ccache

    class EmptyCache:
        credentials: list[Any] = []

        @classmethod
        def loadFile(cls, path: str) -> EmptyCache:  # noqa: N802
            assert path.endswith("missing.ccache")
            return cls()

        def getCredential(self, principal: str) -> None:  # noqa: N802
            assert principal == "krbtgt/CORP.TEST@CORP.TEST"
            return

    monkeypatch.setattr(ccache, "CCache", EmptyCache)
    monkeypatch.setenv("KRB5CCNAME", "previous.ccache")

    result = unpac.request_u2u_pac(
        ccache_path=str(tmp_path / "missing.ccache"),
        username="alice",
        domain="corp.test",
        dc_ip="10.0.0.1",
        asrep_key_hex="aa" * 32,
    )

    assert result == {"ok": False, "error": "No TGT credentials found in ccache"}
    assert os.environ["KRB5CCNAME"] == "previous.ccache"


def test_request_u2u_pac_builds_self_ticket_and_decrypts_pac(monkeypatch: Any) -> None:
    import impacket.krb5.asn1 as asn1
    import impacket.krb5.ccache as ccache
    import impacket.krb5.constants as constants
    import impacket.krb5.crypto as crypto
    import impacket.krb5.kerberosv5 as kerberosv5
    import impacket.krb5.types as krb_types
    import pyasn1.codec.der.decoder as der_decoder
    import pyasn1.codec.der.encoder as der_encoder
    import pyasn1.type.univ as univ

    class EnumValue:
        def __init__(self, value: int) -> None:
            self.value = value

    class Cipher:
        enctype = 18

        def encrypt(self, _key: Any, usage: int, _plain: bytes, _iv: Any) -> bytes:
            assert usage == 7
            return b"authenticator"

        def decrypt(self, _key: Any, usage: int, ciphertext: bytes) -> bytes:
            assert usage == 2
            assert ciphertext == b"encrypted-ticket"
            return b"ticket-plain"

    class Credential:
        def toTGT(self) -> dict[str, Any]:  # noqa: N802
            return {
                "KDC_REP": b"as-rep",
                "cipher": Cipher(),
                "sessionKey": object(),
            }

    class Cache:
        credentials = [Credential()]

        @classmethod
        def loadFile(cls, path: str) -> Cache:  # noqa: N802
            assert path == "alice.ccache"
            return cls()

        def getCredential(self, principal: str) -> Credential:  # noqa: N802
            assert principal == "krbtgt/CORP.TEST@CORP.TEST"
            return self.credentials[0]

    class Principal:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.components_to_asn1 = _Node()

        def from_asn1(self, *_args: Any) -> None:
            return None

    class Ticket:
        def from_asn1(self, value: Any) -> None:
            assert value == _Node()

        def to_asn1(self, *_args: Any) -> _Node:
            return _Node()

    class KerberosTime:
        @staticmethod
        def to_asn1(value: Any) -> str:
            return str(value)

    class Octets:
        def asOctets(self) -> bytes:  # noqa: N802
            return b"pac"

    class AS_REP(_Node):
        pass

    class TGS_REP(_Node):
        pass

    class TGS_REQ(_Node):
        pass

    class AP_REQ(_Node):
        pass

    class Authenticator(_Node):
        pass

    class EncTicketPart(_Node):
        pass

    class AD_IF_RELEVANT(_Node):
        pass

    class TicketAsn1(_Node):
        pass

    decoded_tgt = _Node(ticket=_Node(), crealm="CORP.TEST", cname=_Node())
    decoded_tgs = _Node(ticket=_Node(**{"enc-part": _Node(cipher=b"encrypted-ticket", etype=18)}))
    decoded_ticket = _Node(**{"authorization-data": [_Node(**{"ad-data": b"authorization"})]})
    decoded_ad = [_Node(**{"ad-data": Octets()})]

    def decode(data: bytes, *, asn1Spec: Any) -> list[Any]:  # noqa: N803
        name = type(asn1Spec).__name__
        assert data in {b"as-rep", b"tgs-response", b"ticket-plain", b"authorization"}
        return {
            "AS_REP": [decoded_tgt],
            "TGS_REP": [decoded_tgs],
            "EncTicketPart": [decoded_ticket],
            "AD_IF_RELEVANT": [decoded_ad],
        }[name]

    def seq_set(container: _Node, name: str, value: Any = None) -> Any:
        if value is None:
            value = _Node()
        container[name] = value
        return value

    def seq_set_iter(container: _Node, name: str, values: Any) -> None:
        container[name] = tuple(values)

    monkeypatch.setattr(
        constants,
        "ApplicationTagNumbers",
        SimpleNamespace(AP_REQ=EnumValue(14), TGS_REQ=EnumValue(12)),
    )
    monkeypatch.setattr(
        constants,
        "PreAuthenticationDataTypes",
        SimpleNamespace(PA_TGS_REQ=EnumValue(1)),
    )
    monkeypatch.setattr(
        constants,
        "KDCOptions",
        SimpleNamespace(
            forwardable=EnumValue(1),
            renewable=EnumValue(2),
            canonicalize=EnumValue(3),
            enc_tkt_in_skey=EnumValue(4),
        ),
    )
    monkeypatch.setattr(constants, "PrincipalNameType", SimpleNamespace(NT_UNKNOWN=EnumValue(0)))
    monkeypatch.setattr(constants, "EncryptionTypes", SimpleNamespace(rc4_hmac=EnumValue(23)))
    monkeypatch.setattr(constants, "encodeFlags", lambda values: tuple(values))
    for name, value in {
        "AD_IF_RELEVANT": AD_IF_RELEVANT,
        "AP_REQ": AP_REQ,
        "AS_REP": AS_REP,
        "Authenticator": Authenticator,
        "EncTicketPart": EncTicketPart,
        "TGS_REP": TGS_REP,
        "TGS_REQ": TGS_REQ,
        "Ticket": TicketAsn1,
        "seq_set": seq_set,
        "seq_set_iter": seq_set_iter,
    }.items():
        monkeypatch.setattr(asn1, name, value)
    monkeypatch.setattr(ccache, "CCache", Cache)
    monkeypatch.setattr(crypto, "_enctype_table", {18: Cipher()})
    monkeypatch.setattr(kerberosv5, "sendReceive", lambda *args: b"tgs-response")
    monkeypatch.setattr(krb_types, "KerberosTime", KerberosTime)
    monkeypatch.setattr(krb_types, "Principal", Principal)
    monkeypatch.setattr(krb_types, "Ticket", Ticket)
    monkeypatch.setattr(der_decoder, "decode", decode)
    monkeypatch.setattr(der_encoder, "encode", lambda _value: b"encoded")
    monkeypatch.setattr(univ, "noValue", _Node())
    monkeypatch.setattr(
        unpac,
        "decrypt_pac_credential_info",
        lambda pac_data, asrep_key: {
            "status": "recovered",
            "nt_hash": "11" * 16,
            "lm_hash": "22" * 16,
        },
    )
    monkeypatch.setenv("KRB5CCNAME", "previous.ccache")

    result = unpac.request_u2u_pac(
        ccache_path="alice.ccache",
        username="alice",
        domain="corp.test",
        dc_ip="10.0.0.1",
        asrep_key_hex="aa" * 32,
    )

    assert result == {
        "ok": True,
        "status": "recovered",
        "nt_hash": "11" * 16,
        "lm_hash": "22" * 16,
    }
    assert os.environ["KRB5CCNAME"] == "previous.ccache"


def _configure_drs_test(monkeypatch: Any, mode: str) -> list[Any]:
    import impacket.dcerpc.v5.drsuapi as drsuapi
    import impacket.dcerpc.v5.dtypes as dtypes
    import impacket.dcerpc.v5.rpcrt as rpcrt
    import impacket.dcerpc.v5.transport as transport

    calls: list[Any] = []

    class RpcFailure(Exception):
        pass

    class Dce:
        def connect(self) -> None:
            return None

        def bind(self, _uuid: Any) -> None:
            return None

        def request(self, request: Any) -> Any:
            calls.append(request)
            if len(calls) == 1:
                if mode == "bind":
                    return {"ErrorCode": 5}
                return {"ErrorCode": 0, "phDrs": "handle"}
            if len(calls) == 2:
                if mode == "rpc":
                    raise RpcFailure("rpc failed")
                if mode == "error":
                    return {"ErrorCode": 5}
                if mode == "reply":
                    return {
                        "ErrorCode": 0,
                        "pdwOutVersion": 2,
                        "pmsgOut": {"V2": {"errCode": 9}},
                    }
                return {
                    "ErrorCode": 0,
                    "pdwOutVersion": 2,
                    "pmsgOut": {"V2": {"errCode": 0}},
                }
            return {}

    class Transport:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.dce = Dce()

        def set_credentials(self, *args: Any, **kwargs: Any) -> None:
            return None

        def get_dce_rpc(self) -> Dce:
            return self.dce

    monkeypatch.setattr(drs_addentry, "_structures", lambda: (_Node, _Node))
    monkeypatch.setattr(drs_addentry, "_build_dsname", lambda dn: {"dn": dn})
    monkeypatch.setattr(drs_addentry, "require_impacket", lambda *_args: None)
    monkeypatch.setattr(transport, "SMBTransport", Transport)
    monkeypatch.setattr(rpcrt, "DCERPCException", RpcFailure)
    for name, value in {
        "ATTR": _Node,
        "ATTRVAL": _Node,
        "DRSBind": _Node,
        "DRSUnbind": _Node,
        "MakeAttid": lambda table, oid: f"{oid}:{len(table)}",
        "NULL": None,
    }.items():
        monkeypatch.setattr(drsuapi, name, value)
    monkeypatch.setattr(dtypes, "NULL", None)
    return calls


@pytest.mark.parametrize("mode", ("bind", "rpc", "error", "reply"))
def test_add_entry_modify_reports_native_drs_failures(monkeypatch: Any, mode: str) -> None:
    calls = _configure_drs_test(monkeypatch, mode)

    result = drs_addentry.add_entry_modify(
        _target(),
        object_dn="CN=Alice,DC=corp,DC=test",
        attribute="description",
        value=b"x",
    )

    assert result["ok"] is False
    assert result["stage"] in {"bind", "addentry"}
    if mode == "bind":
        assert "DRSBind rejected" in result["error"]
        assert len(calls) == 1
    elif mode == "rpc":
        assert result["error"] == "rpc failed"
        assert len(calls) == 3
    elif mode == "error":
        assert "DRSAddEntry failed" in result["error"]
        assert len(calls) == 3
    else:
        assert result["reply_err_code"] == 9
        assert result["error"] == "DRSAddEntry reply errCode=9"
        assert len(calls) == 3


def test_add_entry_modify_builds_remote_modify_request(monkeypatch: Any) -> None:
    calls = _configure_drs_test(monkeypatch, "success")

    result = drs_addentry.add_entry_modify(
        _target(),
        object_dn="CN=Alice,DC=corp,DC=test",
        attribute="description",
        value="changed",
    )

    request = calls[1]
    entry = request["pmsgIn"]["V2"]["EntInfList"]["Entinf"]
    attr = entry["AttrBlock"]["pAttr"][0]
    assert result["ok"] is True
    assert result["reply_err_code"] == 0
    assert request["dwInVersion"] == 2
    assert entry["ulFlags"] == drs_addentry.ENTINF_REMOTE_MODIFY
    assert attr["attrTyp"] == "2.5.4.13:0"
    assert attr["AttrVal"]["pAVal"][0]["pVal"] == list("changed".encode("utf-16-le"))
    assert len(calls) == 3


def test_pkinit_auth_falls_back_to_gettgtpkinit_and_captures_material(
    monkeypatch: Any, tmp_path: Path
) -> None:
    pfx = tmp_path / "card.pfx"
    pfx.write_bytes(b"pfx")
    calls: list[list[str]] = []
    asrep_key = "ab" * 32
    nt_hash = "cd" * 16

    monkeypatch.setattr(
        shutil,
        "which",
        lambda name: "gettgtpkinit.py" if name == "gettgtpkinit.py" else None,
    )

    session = Session(tmp_path)

    def fake_run(command: list[str], **kwargs: Any) -> Any:
        calls.append(command)
        if "certipy" in command:
            return SimpleNamespace(
                returncode=1,
                stdout=f"AS-REP encryption key: {asrep_key}\nGot NT hash: {nt_hash}",
                stderr="certipy failed",
            )
        Path(command[-1]).write_bytes(b"ccache")
        assert kwargs["cwd"] == str(session.root)
        return SimpleNamespace(returncode=0, stdout="gettgt ok", stderr="")

    monkeypatch.setattr(pkinit_auth.subprocess, "run", fake_run)
    result = pkinit_auth.PkinitAuth().run(
        _target(),
        session,
        AttackGraph(),
        force=True,
        sam="alice",
        pfx=str(pfx),
        include_secrets=True,
    )

    assert result["ok"] is True
    assert result["method"] == "gettgtpkinit"
    assert Path(result["ccache"]).is_file()
    assert result["asrep_key"] == asrep_key
    assert result["nt_hash_present"] is True
    assert result["nt_hash"] == nt_hash
    assert len(calls) == 2


def test_esc_chain_dispatches_modern_and_relay_runners(monkeypatch: Any, tmp_path: Path) -> None:
    modern_calls: list[dict[str, Any]] = []
    relay_calls: list[dict[str, Any]] = []

    class ModernRunner:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            modern_calls.append(kwargs)
            return {"ok": True, "method": "modern"}

    class RelayRunner:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            relay_calls.append(kwargs)
            return {"ok": True, "method": "relay"}

    monkeypatch.setattr(adcs_esc, "Esc9", ModernRunner)
    monkeypatch.setattr(adcs_esc, "Esc8RelayWorkflow", RelayRunner)

    modern = esc_chain.EscChain().run(
        _target(),
        Session(tmp_path / "modern"),
        AttackGraph(),
        force=True,
        template="UserTemplate",
        ca="CORP-CA",
        esc="9",
    )
    relay = esc_chain.EscChain().run(
        _target(),
        Session(tmp_path / "relay"),
        AttackGraph(),
        force=True,
        template="UserTemplate",
        ca="CORP-CA",
        esc=8,
        coerce_host="dc01",
        allow_hosts=["dc01"],
        listener="10.0.0.5",
        duration_seconds=30,
    )

    assert modern["esc"] == "ESC9"
    assert modern["cert_request"]["method"] == "modern"
    assert relay["esc"] == "ESC8"
    assert relay["cert_request"]["method"] == "relay"
    assert relay["pkinit_auth"] == {}
    assert modern_calls[0]["template"] == "UserTemplate"
    assert relay_calls[0]["coerce_host"] == "dc01"


def test_script_exec_builds_authentication_argv_for_native_modes(monkeypatch: Any) -> None:
    captured: list[tuple[list[str], dict[str, Any]]] = []

    monkeypatch.setattr(impacket_exec.shutil, "which", lambda name: f"/bin/{name}")

    def fake_run(command: list[str], **kwargs: Any) -> Any:
        captured.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(impacket_exec.subprocess, "run", fake_run)
    targets = (
        (_target(use_kerberos=True), ("-k", "-no-pass"), None),
        (_target(hashes="lm:nt", password=None), ("-hashes", "lm:nt"), None),
        (_target(aes_key="aa" * 32, password=None), ("-aesKey", "aa" * 32, "-k"), None),
        (_target(), (), "Secret1!\n"),
        (_target(dc_ip="", password=None), ("-no-pass",), None),
    )

    for target, expected_auth, expected_input in targets:
        result = impacket_exec._run_script_exec(target, "server", "whoami", "atexec", 3)
        command, kwargs = captured[-1]
        assert result["status"] == "executed"
        assert all(item in command for item in expected_auth)
        assert kwargs["input"] == expected_input
        if target.dc_ip:
            assert "-dc-ip" in command
        else:
            assert "-dc-ip" not in command
