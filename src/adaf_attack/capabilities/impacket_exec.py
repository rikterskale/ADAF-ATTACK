"""Unified remote-execution wrapper (wmiexec / smbexec / dcomexec / atexec).

Runs a single command and records execution status in the session. WMI and
script-backed methods capture output; smbexec may stream output to its own
console. Every method reports whether execution actually completed.
"""

from __future__ import annotations

import contextlib
import json
import shlex
import shutil
import subprocess
from typing import Any, cast

from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.impacket_helper import require_impacket
from adaf_attack.core.redaction import redact
from adaf_attack.core.registry import (
    ApprovalPolicy,
    RiskLevel,
    RollbackClass,
    SafetyProfile,
    register_capability,
)
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
        interface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        wbem_level1_login = wmi.IWbemLevel1Login(interface)
        wbem_services = wbem_level1_login.NTLMLogin("//./root/cimv2", NULL, NULL)
        wbem_level1_login.RemRelease()
        win32_process, _ = wbem_services.GetObject("Win32_Process")
        result = win32_process.Create(command, "C:\\", None)
        return {"return_value": int(result.ReturnValue), "pid": int(result.ProcessId)}
    finally:
        with contextlib.suppress(Exception):
            dcom.disconnect()


def _run_script_exec(
    target: Target, host: str, command: str, method: str, timeout: float
) -> dict[str, Any]:
    """Invoke an Impacket script using argv-only execution and capture status."""
    binary = shutil.which(f"impacket-{method}") or shutil.which(f"{method}.py")
    if not binary:
        raise RuntimeError(f"No {method} Impacket script found on PATH")
    argv = [binary]
    password_input: str | None = None
    if target.use_kerberos:
        argv.extend(["-k", "-no-pass"])
    elif target.hashes:
        argv.extend(["-hashes", target.hashes])
    elif target.aes_key:
        argv.extend(["-aesKey", target.aes_key, "-k", "-no-pass"])
    elif target.password:
        password_input = target.password + "\n"
    else:
        argv.append("-no-pass")
    if target.dc_ip:
        argv.extend(["-dc-ip", target.dc_ip])
    principal = (
        f"{target.domain}/{target.username}" if target.domain else str(target.username or "")
    )
    argv.extend([f"{principal}@{host}", command])
    completed = subprocess.run(
        argv,
        input=password_input,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return {
        "status": "executed" if completed.returncode == 0 else "failed",
        "return_code": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
        "argv": [item if item != target.password else "[REDACTED]" for item in argv],
    }


@register_capability(
    id="impacket-exec",
    summary="Scoped remote execute via wmiexec / smbexec / dcomexec / atexec with execution status",
    category="lateral-movement",
    tags=("wmiexec", "smbexec", "dcomexec", "atexec", "impacket"),
    destructive=True,
    safety=SafetyProfile(
        risk=RiskLevel.DESTRUCTIVE,
        approval=ApprovalPolicy.SCOPED_TOKEN,
        rollback=RollbackClass.MANUAL,
        network_side_effect=True,
        modifies_directory=True,
    ),
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
                outcome = _run_script_exec(
                    target,
                    host,
                    str(command),
                    method,
                    float(kwargs.get("timeout_seconds") or 60),
                )
        except Exception as exc:
            outcome = {"error": str(exc)[:400]}

        result = {
            "ok": "error" not in outcome and outcome.get("return_code", 0) == 0,
            "status": "completed"
            if "error" not in outcome and outcome.get("return_code", 0) == 0
            else "failed",
            "host": host,
            "method": method,
            "command": str(command),
            "outcome": outcome,
        }
        safe_result = redact(result, include_secrets=include_secrets)
        out = session.path("impacket-exec.json")
        out.write_text(json.dumps(safe_result, indent=2, default=str), encoding="utf-8")
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
        return cast(dict[str, Any], safe_result)
