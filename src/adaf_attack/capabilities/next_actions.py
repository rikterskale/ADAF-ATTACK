"""Turn evidence-backed graph chains into reviewed next-action plans.

Suggestions are filtered by what the current session graph has actually proven.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adaf_attack.core.command_templates import build_exploit_commands
from adaf_attack.core.confidence import score_chain
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

# terminal_relation → (capability, risk, requires_approval, required_evidence)
# required_evidence = set of relation kinds that must already exist in the graph
ACTION_MAP: dict[str, tuple[str, str, bool, frozenset[str]]] = {
    "WriteKeyCredentialLink": (
        "shadow-pkinit-workflow",
        "high",
        True,
        frozenset({"WriteKeyCredentialLink"}),
    ),
    "HasKeyCredentialLink": (
        "pkinit-auth",
        "medium",
        False,
        frozenset({"HasKeyCredentialLink"}),
    ),
    "WriteRBCD": (
        "rbcd-ticket-workflow",
        "high",
        True,
        frozenset({"WriteRBCD", "AllowedToAct"}),
    ),
    "AllowedToAct": (
        "s4u-abuse",
        "high",
        True,
        frozenset({"AllowedToAct", "WriteRBCD"}),
    ),
    "HasSPN": (
        "kerberoast",
        "medium",
        False,
        frozenset({"HasSPN"}),
    ),
    "CanASREP": (
        "asrep-roast",
        "medium",
        False,
        frozenset({"CanASREP"}),
    ),
    "DCSync": (
        "dcsync",
        "high",
        True,
        frozenset({"DCSync", "GetChanges", "GetChangesAll"}),
    ),
    "GetChangesAll": (
        "dcsync",
        "high",
        True,
        frozenset({"DCSync", "GetChangesAll"}),
    ),
    "WriteGPO": (
        "gpo-abuse",
        "high",
        True,
        frozenset({"WriteGPO", "WriteSYSVOL"}),
    ),
    "WriteSYSVOL": (
        "gpo-sysvol",
        "high",
        True,
        frozenset({"WriteSYSVOL"}),
    ),
    "SpoolerOpen": (
        "coerce",
        "high",
        True,
        frozenset({"SpoolerOpen", "EfsrpcOpen"}),
    ),
    "EfsrpcOpen": (
        "coerce",
        "high",
        True,
        frozenset({"SpoolerOpen", "EfsrpcOpen"}),
    ),
    "ESC1Enrollable": (
        "esc-chain",
        "high",
        False,
        frozenset({"ESC1", "ESC1Enrollable", "ESC2", "ESC6"}),
    ),
    "ESC1": (
        "esc-chain",
        "high",
        False,
        frozenset({"ESC1", "ESC1Enrollable"}),
    ),
    "ESC6": (
        "esc-chain",
        "high",
        False,
        frozenset({"ESC6"}),
    ),
    "ReadGMSAPassword": (
        "laps-read",
        "high",
        False,
        frozenset({"ReadGMSAPassword", "GMSAPasswordReadable"}),
    ),
    "GMSAPasswordReadable": (
        "laps-read",
        "high",
        False,
        frozenset({"GMSAPasswordReadable"}),
    ),
    "TrustedBy": (
        "trusts-enum",
        "medium",
        False,
        frozenset({"TrustedBy"}),
    ),
}


def _graph_relations(graph: AttackGraph) -> set[str]:
    return {e.kind for e in getattr(graph, "edges", [])}


@register_capability(
    id="next-actions",
    summary="Recommend policy-gated next actions from current graph evidence only",
    category="analysis",
    tags=("recommendations", "paths", "workflow", "opsec", "evidence"),
)
class NextActions:
    def run(
        self, target: Target, session: Session, graph: AttackGraph, **kwargs: Any
    ) -> dict[str, Any]:
        if not graph.nodes:
            source = Path(kwargs.get("graph_path") or session.path("graph.json"))
            if source.is_file():
                graph = AttackGraph.from_file(source)
            else:
                raise RuntimeError("No graph available. Run enumeration or pass graph_path.")

        observed = _graph_relations(graph)
        chains = graph.rank_exploit_chains(limit=int(kwargs.get("limit") or 30))
        if not hasattr(graph, "edges"):
            observed.update(str(chain["terminal_relation"]) for chain in chains)

        actions: list[dict[str, Any]] = []
        seen: set[str] = set()

        for chain in chains:
            relation = str(chain["terminal_relation"])
            mapped = ACTION_MAP.get(relation)
            if not mapped:
                continue

            capability, risk, approval, required = mapped
            if capability in seen:
                continue

            # Evidence gate: at least one required relation must already be present
            if required and not (required & observed):
                continue

            conf = score_chain(
                terminal_relation=relation,
                path_length=int(chain.get("length") or 1),
                edge_kinds=list(chain.get("edges") or []),
            )

            examples = build_exploit_commands(
                chain, target, operator_user=target.username
            )
            primary = examples[0] if examples else None

            # Prefer template risk/approval when available; fall back to ACTION_MAP
            if primary:
                capability = primary["capability"]
                risk = primary["risk"]
                approval = primary["approval_required"]

            seen.add(capability)
            actions.append(
                {
                    "capability": capability,
                    "risk": risk,
                    "approval_required": approval,
                    "reason": chain.get("impact"),
                    "evidence_relation": relation,
                    "evidence_present": sorted(required & observed),
                    "score": chain.get("score"),
                    "confidence": conf["confidence"],
                    "confidence_rank": conf["confidence_rank"],
                    "command": primary["command"]
                    if primary
                    else (
                        f"adaf-attack plan {capability} -d {target.domain} --dc-ip {target.dc_ip}"
                    ),
                    "example_commands": examples,
                    "path": chain.get("path"),
                    "terminal_relation": relation,
                }
            )

        # Prefer higher confidence, then lower graph score
        actions.sort(key=lambda a: (-a["confidence_rank"], a.get("score") or 99))

        result = {
            "domain": target.domain,
            "observed_relations": sorted(observed),
            "actions": actions,
            "count": len(actions),
        }
        session.path("next-actions.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        session.log("next-actions.complete", count=len(actions))
        return result
