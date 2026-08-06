"""Turn evidence-backed graph chains into reviewed next-action plans."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

ACTION_MAP = {
    "WriteKeyCredentialLink": ("shadow-pkinit-workflow", "high", True),
    "WriteRBCD": ("rbcd-ticket-workflow", "high", True),
    "AllowedToAct": ("rbcd-ticket-workflow", "high", True),
    "HasSPN": ("kerberoast", "medium", False),
    "DCSync": ("acl-enum", "high", False),
    "WriteGPO": ("gpo-impact-plan", "high", True),
    "SpoolerOpen": ("coercion-map", "high", True),
    "EfsrpcOpen": ("coercion-map", "high", True),
    "TrustedBy": ("forest-campaign", "medium", False),
    "GPPPasswordExposure": ("ticket-lifecycle", "high", False),
}


@register_capability(
    id="next-actions",
    summary="Recommend policy-gated next actions from current graph evidence",
    category="analysis",
    tags=("recommendations", "paths", "workflow", "opsec"),
)
class NextActions:
    def run(self, target: Target, session: Session, graph: AttackGraph, **kwargs: Any) -> dict[str, Any]:
        if not graph.nodes:
            source = Path(kwargs.get("graph_path") or session.path("graph.json"))
            if source.is_file():
                graph = AttackGraph.from_file(source)
            else:
                raise RuntimeError("No graph available. Run enumeration or pass graph_path.")
        chains = graph.rank_exploit_chains(limit=int(kwargs.get("limit") or 20))
        actions: list[dict[str, Any]] = []
        seen: set[str] = set()
        for chain in chains:
            relation = str(chain["terminal_relation"])
            mapped = ACTION_MAP.get(relation)
            if not mapped or mapped[0] in seen:
                continue
            capability, risk, approval = mapped
            seen.add(capability)
            actions.append(
                {
                    "capability": capability,
                    "risk": risk,
                    "approval_required": approval,
                    "reason": chain["impact"],
                    "evidence_relation": relation,
                    "score": chain["score"],
                    "command": f"adaf-attack plan {capability} -d {target.domain} --dc-ip {target.dc_ip}",
                }
            )
        result = {"domain": target.domain, "actions": actions, "count": len(actions)}
        session.path("next-actions.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        session.log("next-actions.complete", count=len(actions))
        return result
