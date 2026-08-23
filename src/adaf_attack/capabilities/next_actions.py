"""Turn evidence-backed graph chains into reviewed next-action plans.

Suggestions are filtered by what the current session graph has actually proven.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adaf_attack.core.command_templates import build_exploit_commands
from adaf_attack.core.confidence import score_chain
from adaf_attack.core.graph import EXPLOIT_PROFILES, AttackGraph
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
        """Build review-only actions from graph evidence.

        Accepted ``-P`` values are ``graph_path`` (path-like), ``limit``
        (positive integer), and the standard runner controls. The capability
        writes ``next-actions.json`` and never executes the suggested command.
        It is read-only and does not create rollback entries.
        """
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
                examples = build_exploit_commands(chain, target, operator_user=target.username)
                if not examples:
                    continue
                fallback_example = examples[0]
                seen_key = f"plan:{relation}"
                if seen_key in seen:
                    continue
                seen.add(seen_key)
                observed_for_chain = sorted(
                    {str(item) for item in chain.get("edges") or []} & observed
                )
                actions.append(
                    {
                        "capability": fallback_example["capability"],
                        "risk": fallback_example["risk"],
                        "approval_required": fallback_example["approval_required"],
                        "reason": (
                            f"Unmapped relation {relation}; review the path and capability "
                            "catalog before executing anything."
                        ),
                        "rationale": (
                            f"The graph contains {relation} evidence, but no execution "
                            "template is registered for it."
                        ),
                        "evidence_relation": relation,
                        "evidence_present": observed_for_chain,
                        "evidence_missing": [],
                        "score": chain.get("score"),
                        "confidence": "unknown",
                        "confidence_rank": 0,
                        "command": fallback_example["command"],
                        "example_commands": examples,
                        "follow_on_commands": fallback_example.get("follow_on_commands", []),
                        "path": chain.get("path"),
                        "terminal_relation": relation,
                        "review_only": True,
                    }
                )
                continue

            capability, risk, approval, required = mapped
            if capability in seen:
                continue

            # Evidence gate: at least one required relation must already be present
            if required and not (required & observed):
                continue

            chain_profile = dict(EXPLOIT_PROFILES.get(relation, {}))
            if chain.get("confidence"):
                chain_profile["confidence"] = chain["confidence"]
            conf = score_chain(
                terminal_relation=relation,
                path_length=int(chain.get("length") or 1),
                edge_kinds=list(chain.get("edges") or []),
                profile=chain_profile,
            )

            examples = build_exploit_commands(chain, target, operator_user=target.username)
            primary: dict[str, Any] | None = examples[0] if examples else None

            # Prefer template risk/approval when available; fall back to ACTION_MAP
            if primary and not primary.get("fallback"):
                capability = primary["capability"]
                risk = primary["risk"]
                approval = primary["approval_required"]
            elif primary and primary.get("fallback"):
                prefix = f"adaf-attack plan {relation}"
                if str(primary["command"]).startswith(prefix):
                    primary = dict(primary)
                    primary["command"] = str(primary["command"]).replace(
                        prefix, f"adaf-attack plan {capability}", 1
                    )

            evidence_present = sorted(required & observed)
            evidence_missing = sorted(required - observed)
            impact = str(
                chain.get("impact") or EXPLOIT_PROFILES.get(relation, {}).get("impact") or ""
            )
            rationale = (
                f"{impact or 'Evidence-backed terminal condition'}; observed "
                f"{', '.join(evidence_present) or relation}. "
                f"Confidence is {conf['confidence']} based on the relation and "
                f"{len(chain.get('edges') or [])} path edge(s)."
            )

            seen.add(capability)
            actions.append(
                {
                    "capability": capability,
                    "risk": risk,
                    "approval_required": approval,
                    "reason": impact,
                    "rationale": rationale,
                    "evidence_relation": relation,
                    "evidence_present": evidence_present,
                    "evidence_missing": evidence_missing,
                    "score": chain.get("score"),
                    "confidence": conf["confidence"],
                    "confidence_rank": conf["confidence_rank"],
                    "command": primary["command"]
                    if primary
                    else (
                        f"adaf-attack plan {capability} -d {target.domain} --dc-ip {target.dc_ip}"
                    ),
                    "example_commands": examples,
                    "follow_on_commands": (primary or {}).get("follow_on_commands", []),
                    "path": chain.get("path"),
                    "terminal_relation": relation,
                }
            )

        # Prefer higher confidence, then lower graph score
        actions.sort(key=lambda a: (-a["confidence_rank"], a.get("score") or 99))

        result = {
            "domain": target.domain,
            "target": target.as_dict(),
            "session_path": str(session.root),
            "observed_relations": sorted(observed),
            "actions": actions,
            "count": len(actions),
        }
        session.path("next-actions.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        session.log("next-actions.complete", count=len(actions))
        return result
