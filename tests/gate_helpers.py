"""Shared fakes for branch-closure gate tests (not collected by pytest)."""

from __future__ import annotations

from typing import Any

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


class Attr:
    def __init__(self, value: Any = None) -> None:
        self.value = value
        self.values = value if isinstance(value, list) else ([] if value is None else [value])
        self.raw_values = self.values

    def __bool__(self) -> bool:
        return self.value is not None and self.value != []

    def __str__(self) -> str:
        return str(self.value)


class Entry:
    def __init__(self, **values: Any) -> None:
        self._values = {key: Attr(value) for key, value in values.items()}

    def __getattr__(self, name: str) -> Attr:
        if name in self._values:
            return self._values[name]
        alt = name.replace("_", "-")
        if alt in self._values:
            return self._values[alt]
        return Attr()

    def __getitem__(self, name: str) -> Attr:
        return self.__getattr__(name)


class Conn:
    def __init__(self, by_filter: dict[str, list[Entry]] | None = None) -> None:
        self.by_filter = by_filter or {}
        self.entries: list[Entry] = []
        self.result = {"result": 0, "description": "success"}
        self.modifies: list[Any] = []
        self.adds: list[Any] = []
        self.deletes: list[str] = []
        self.unbound = False

    def search(self, base: str, search_filter: str, **kwargs: Any) -> bool:
        for key, entries in self.by_filter.items():
            if key in search_filter or search_filter in key or key in base:
                self.entries = entries
                return True
        if base in self.by_filter:
            self.entries = self.by_filter[base]
            return True
        self.entries = []
        return True

    def modify(self, dn: str, changes: Any) -> bool:
        self.modifies.append((dn, changes))
        return True

    def add(self, dn: str, attributes: Any = None) -> bool:
        self.adds.append((dn, attributes))
        return True

    def delete(self, dn: str) -> bool:
        self.deletes.append(dn)
        return True

    def unbind(self) -> None:
        self.unbound = True


class FailModifyConn(Conn):
    """Connection whose modify() always fails, to exercise ok=False branches."""

    def modify(self, dn: str, changes: Any) -> bool:
        self.modifies.append((dn, changes))
        return False


def target(**kwargs: Any) -> Target:
    values = {
        "domain": "corp.test",
        "dc_ip": "10.0.0.1",
        "username": "alice",
        "password": "Secret1!",
        "ldaps": True,
    }
    values.update(kwargs)
    return Target(**values)


def sid_entry(sam: str, dn: str, sid: str = "S-1-5-21-1-2-3-1104") -> Entry:
    return Entry(
        sAMAccountName=sam,
        distinguishedName=dn,
        objectSid=sid,
        member=[],
        servicePrincipalName=[],
    )


def patch_ldap(monkeypatch: Any, module: Any, conn: Conn, base: str = "DC=corp,DC=test") -> None:
    monkeypatch.setattr(
        module, "ldap_connect", lambda t: (conn, base, "CN=Configuration,DC=corp,DC=test")
    )


def session(tmp_path: Any) -> Session:
    return Session(tmp_path)


def graph() -> AttackGraph:
    return AttackGraph()


def install_dpapi_lsarpc_mocks(
    monkeypatch: Any,
    *,
    version: int = 2,
    fail_at: str | None = None,
    error_text: str = "boom",
) -> dict[str, int]:
    """Stub the LSARPC/DCERPC surface used by DpapiDomainBackup.

    fail_at: None | "bind" | "open" | "preferred" | "key".
    Returns a call-counter dict so tests can assert retrieval order.
    """

    import struct as _struct
    import sys
    import types

    calls = {"bind": 0, "retrieve": 0}

    class _Smb:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            return None

        def kerberosLogin(self, *args: Any, **kwargs: Any) -> None:
            return None

        def login(self, *args: Any, **kwargs: Any) -> None:
            return None

        def getSessionKey(self) -> bytes:
            return b"session-key"

    class _Rpc:
        def get_dce_rpc(self) -> _Dce:
            return _Dce()

    class _Dce:
        def connect(self) -> None:
            if fail_at == "connect":
                raise RuntimeError(error_text)

        def bind(self, _uuid: Any) -> None:
            calls["bind"] += 1
            if fail_at == "bind":
                raise RuntimeError(error_text)

    def _fail(step: str) -> None:
        if fail_at == step:
            if step in ("preferred", "key"):
                raise RuntimeError("rpc_s_access_denied")
            raise RuntimeError(error_text)

    def _fake_open(_dce: Any, _access: Any) -> Any:
        _fail("open")
        return {"PolicyHandle": object()}

    guid = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")

    def _secret() -> bytes:
        if version == 1:
            return _struct.pack("<I", 1) + b"LEGACYKEY"
        return _struct.pack("<III", version, 4, 0) + b"KEY!" + b"CERT"

    def _fake_retrieve(_dce: Any, _handle: Any, name: str) -> bytes:
        calls["retrieve"] += 1
        if name.endswith("_PREFERRED"):
            _fail("preferred")
            return guid
        _fail("key")
        return _secret()

    lsad_mod = types.ModuleType("impacket.dcerpc.v5.lsad")
    lsad_mod.MSRPC_UUID_LSAD = b"uuid-lsad"
    lsad_mod.POLICY_GET_PRIVATE_INFORMATION = 0x00000400
    lsad_mod.hLsarOpenPolicy2 = _fake_open
    lsad_mod.hLsarRetrievePrivateData = _fake_retrieve
    transport_mod = types.ModuleType("impacket.dcerpc.v5.transport")
    transport_mod.SMBTransport = lambda *a, **k: _Rpc()
    smb_mod = types.ModuleType("impacket.smbconnection")
    smb_mod.SMBConnection = _Smb
    crypto_mod = types.ModuleType("impacket.crypto")
    crypto_mod.decryptSecret = lambda key, value: value

    monkeypatch.setitem(sys.modules, "impacket.smbconnection", smb_mod)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.lsad", lsad_mod)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.transport", transport_mod)
    monkeypatch.setitem(sys.modules, "impacket.crypto", crypto_mod)
    # If the real parent package is already imported, `from pkg import mod`
    # resolves via the package attribute first — patch that path too.
    parent = sys.modules.get("impacket.dcerpc.v5")
    if parent is not None:
        monkeypatch.setattr(parent, "lsad", lsad_mod, raising=False)
        monkeypatch.setattr(parent, "transport", transport_mod, raising=False)
    return calls


def install_drsuapi_mocks(
    monkeypatch: Any,
    *,
    fail_at: str | None = None,
    error_code: int = 0,
) -> dict[str, int]:
    """Stub the MS-DRSR drsuapi surface used by core.drs_sidhistory.

    fail_at: None | "connect" | "bind" | "bind_call" | "add_call".
    Returns a call-counter dict for assertions.
    """
    import sys
    import types

    calls = {"connect": 0, "iface_bind": 0, "requests": 0}

    class _FakeNdr:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self._fields: dict[Any, Any] = {}

        def __setitem__(self, key: Any, value: Any) -> None:
            self._fields[key] = value

        def __getitem__(self, key: Any) -> Any:
            if key not in self._fields:
                self._fields[key] = _FakeNdr()
            return self._fields[key]

        def __len__(self) -> int:
            return 8

    class _Resp(_FakeNdr):
        def __init__(self, items: dict[Any, Any] | None = None) -> None:
            super().__init__()
            if items:
                self._fields.update(items)

    class _Dce:
        def connect(self) -> None:
            calls["connect"] += 1
            if fail_at == "connect":
                raise RuntimeError("connection refused")

        def bind(self, _uuid: Any) -> None:
            calls["iface_bind"] += 1
            if fail_at == "bind":
                raise RuntimeError("access denied")

        def request(self, obj: Any) -> _Resp:
            calls["requests"] += 1
            if type(obj).__name__ == "DRSUnbind":
                raise RuntimeError("unbind boom")
            if type(obj).__name__ == "DRSBind":
                if fail_at == "bind_call":
                    raise RuntimeError("rpc_s_access_denied")
                if fail_at == "bind_response":
                    return _Resp({"ErrorCode": 8453, "phDrs": b"drs-handle"})
                return _Resp({"ErrorCode": 0, "phDrs": b"drs-handle"})
            if fail_at == "add_call":
                rpcrt = sys.modules["impacket.dcerpc.v5.rpcrt"]
                raise rpcrt.DCERPCException("unwillingToPerform")
            return _Resp({"ErrorCode": error_code})

    class _Rpc:
        def get_dce_rpc(self) -> _Dce:
            return _Dce()

        def set_credentials(self, *args: Any, **kwargs: Any) -> None:
            return None

    class _Transport:
        def __new__(cls, *args: Any, **kwargs: Any) -> _Rpc:
            return _Rpc()

    ndr_mod = types.ModuleType("impacket.dcerpc.v5.ndr")
    ndr_mod.NDRSTRUCT = _FakeNdr
    ndr_mod.NDRUNION = _FakeNdr
    ndr_mod.NDRCALL = _FakeNdr
    ndr_mod.DWORD = int
    dtypes_mod = types.ModuleType("impacket.dcerpc.v5.dtypes")
    dtypes_mod.DWORD = int
    dtypes_mod.GUID = _FakeNdr
    dtypes_mod.LPWSTR = str
    drsuapi_mod = types.ModuleType("impacket.dcerpc.v5.drsuapi")
    drsuapi_mod.MSRPC_UUID_DRSUAPI = b"drsuapi-uuid"
    drsuapi_mod.NULL = None
    drsuapi_mod.DRS_HANDLE = bytes
    drsuapi_mod.NT4SID = bytes
    drsuapi_mod.DRSBind = type("DRSBind", (_FakeNdr,), {})
    drsuapi_mod.DRSUnbind = type("DRSUnbind", (_FakeNdr,), {})
    transport_mod = types.ModuleType("impacket.dcerpc.v5.transport")
    transport_mod.SMBTransport = _Transport
    rpcrt_mod = types.ModuleType("impacket.dcerpc.v5.rpcrt")

    class DCERPCException(Exception):
        pass

    rpcrt_mod.DCERPCException = DCERPCException

    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.ndr", ndr_mod)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.dtypes", dtypes_mod)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.drsuapi", drsuapi_mod)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.transport", transport_mod)
    monkeypatch.setitem(sys.modules, "impacket.dcerpc.v5.rpcrt", rpcrt_mod)
    parent = sys.modules.get("impacket.dcerpc.v5")
    if parent is not None:
        monkeypatch.setattr(parent, "ndr", ndr_mod, raising=False)
        monkeypatch.setattr(parent, "dtypes", dtypes_mod, raising=False)
        monkeypatch.setattr(parent, "drsuapi", drsuapi_mod, raising=False)
        monkeypatch.setattr(parent, "transport", transport_mod, raising=False)
        monkeypatch.setattr(parent, "rpcrt", rpcrt_mod, raising=False)
    return calls


class NoImpacketFinder:
    """Meta-path finder that makes `import impacket` raise ImportError."""

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        if fullname == "impacket" or fullname.startswith("impacket."):
            raise ImportError(f"no impacket ({fullname})")
        return None


def hide_impacket(monkeypatch: Any) -> None:
    """Force `import impacket` to fail for the duration of the test."""
    import builtins
    import sys

    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "impacket" or name.startswith("impacket."):
            raise ImportError("no impacket")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(sys, "meta_path", [NoImpacketFinder()], raising=False)
