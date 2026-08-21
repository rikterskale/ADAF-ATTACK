"""Read-only, deterministic engagement views for the CLI and TUI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adaf_attack.core.graph import EXPLOIT_PROFILES, AttackGraph
from adaf_attack.core.registry import Capability
from adaf_attack.core.ux import (
    capability_phase,
    capability_prerequisites,
    evaluate_prerequisites,
    session_findings_dashboard,
)

MODES = ("OBSERVE", "VALIDATE", "EMULATE")
RANKING_MODES = ("balanced", "fastest", "quietest", "safest", "least-disruptive", "purple-team")
MISSIONS = (
    (
        "baseline-ad-security",
        "Baseline AD security",
        ("ldap-enum", "acl-enum", "adcs-enum", "attack-paths"),
    ),
    ("tier-0-paths", "Find paths to Tier 0", ("ldap-enum", "attack-paths", "next-actions")),
    (
        "credential-exposure",
        "Validate credential exposure",
        ("asrep-roast", "kerberoast", "gmsa-laps-enum"),
    ),
    ("adcs-validation", "Validate AD CS", ("adcs-enum", "adcs-validation", "esc-chain")),
    ("lateral-movement", "Test lateral movement", ("attack-paths", "impacket-exec", "s4u-abuse")),
    (
        "purple-team",
        "Purple-team emulation",
        ("campaign-compose", "campaign-run", "purple-handoff"),
    ),
    ("known-finding", "Investigate a known finding", ("finding", "attack-paths", "report")),
)


def _load(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def capability_review(
    cap: Capability,
    *,
    target: dict[str, Any] | None = None,
    session: Path | None = None,
) -> dict[str, Any]:
    """Common pre-execution review contract, including success and telemetry."""
    phase = capability_phase(cap)
    destructive = bool(cap.destructive)
    feasibility = evaluate_prerequisites(cap.id, session=session)
    prereqs = capability_prerequisites(cap.id)
    prereqs["best_run_after"] = feasibility["required"]
    return {
        "id": cap.id,
        "summary": cap.summary,
        "plain_language": f"{cap.summary}. Review scope and authorization before continuing.",
        "phase": phase,
        "risk": {
            "level": "R3" if destructive else "R1",
            "destructive": destructive,
            "noise": "high"
            if destructive
            else ("low" if phase in {"analysis", "export"} else "medium"),
        },
        "operational_modes": list(MODES) if destructive else ["OBSERVE", "VALIDATE"],
        "prerequisites": prereqs,
        "feasibility": {
            "available": True,
            "applicable": True,
            "prerequisite_complete": feasibility["status"]
            in {"not-required", "satisfied", "unverified"},
            "currently_executable": feasibility["status"] != "missing",
            "prerequisites": feasibility,
        },
        "success_criteria": [
            "Capability completes without an unclassified error",
            "Evidence is captured in the session",
            "Results are validated before reporting",
        ],
        "expected_telemetry": [
            "Directory service activity"
            if phase in {"discovery", "enumeration"}
            else "Capability-specific telemetry",
            "Session audit event",
            "Detection validation status (operator supplied)",
        ],
        "rollback": {
            "required": destructive,
            "readiness": "recorded before execution" if destructive else "not applicable",
            "verification": "required after cleanup" if destructive else "not applicable",
        },
        "target": target or {},
    }


def _rank_score(factors: dict[str, int], ranking: str) -> int:
    weights = {
        "balanced": {
            "exploitability": 2,
            "evidence_quality": 2,
            "expected_value": 2,
            "risk": 1,
            "noise": 1,
            "rollback_quality": 1,
            "prerequisite_satisfaction": 1,
            "detection_value": 1,
        },
        "fastest": {
            "expected_value": 3,
            "prerequisite_satisfaction": 3,
            "exploitability": 2,
            "risk": 1,
        },
        "quietest": {"noise": 4, "evidence_quality": 2, "risk": 1},
        "safest": {"risk": 4, "rollback_quality": 3, "prerequisite_satisfaction": 2},
        "least-disruptive": {"risk": 3, "noise": 3, "rollback_quality": 2},
        "purple-team": {"detection_value": 4, "evidence_quality": 2, "expected_value": 2},
    }
    selected = weights.get(ranking, weights["balanced"])
    return sum(factors.get(name, 0) * weight for name, weight in selected.items())


def _next_actions(
    session: Path, findings: list[dict[str, Any]], edges: int, ranking: str
) -> list[dict[str, Any]]:
    actions = []
    for finding in findings:
        if str(finding.get("status", "open")).lower() in {"closed", "mitigated"}:
            continue
        severity = str(finding.get("severity", "unknown")).lower()
        confidence = str(finding.get("confidence", "unknown")).lower()
        factors = {
            "exploitability": int(finding.get("exploitability", 10)),
            "evidence_quality": 25 if finding.get("evidence") else 8,
            "expected_value": {"critical": 30, "high": 24, "medium": 16, "low": 8}.get(severity, 4),
            "risk": 15,
            "noise": 15 if finding.get("noise") in {None, "low"} else 5,
            "rollback_quality": 15 if finding.get("rollback_quality", True) else 3,
            "prerequisite_satisfaction": 15 if finding.get("prerequisites_satisfied", True) else 2,
            "detection_value": 15 if finding.get("detection_value") else 5,
        }
        factors["expected_value"] += {"confirmed": 10, "high": 7, "medium": 3}.get(confidence, 0)
        score = _rank_score(factors, ranking)
        actions.append(
            {
                "id": f"finding:{finding.get('id') or finding.get('title')}",
                "action": "Validate and triage finding",
                "why": "An open finding still needs evidence or a decision.",
                "score": score,
                "risk": "R1",
                "ranking_factors": factors,
            }
        )
    if edges:
        actions.append(
            {
                "id": "rank-attack-paths",
                "action": "Rank evidence-backed attack paths",
                "why": "The session contains graph relationships that can be inspected offline.",
                "score": _rank_score(
                    {
                        "exploitability": 25,
                        "evidence_quality": 25,
                        "expected_value": 24,
                        "risk": 15,
                        "noise": 15,
                        "rollback_quality": 15,
                        "prerequisite_satisfaction": 15,
                        "detection_value": 15,
                    },
                    ranking,
                ),
                "risk": "R1",
                "ranking_factors": {
                    "exploitability": 25,
                    "evidence_quality": 25,
                    "expected_value": 24,
                    "risk": 15,
                    "noise": 15,
                    "rollback_quality": 15,
                    "prerequisite_satisfaction": 15,
                    "detection_value": 15,
                },
            }
        )
    if not actions:
        actions.append(
            {
                "id": "generate-report",
                "action": "Generate engagement deliverables",
                "why": "No open action is blocking reporting.",
                "score": _rank_score(
                    {
                        "expected_value": 8,
                        "risk": 15,
                        "noise": 15,
                        "rollback_quality": 15,
                        "prerequisite_satisfaction": 15,
                        "detection_value": 5,
                    },
                    ranking,
                ),
                "risk": "R1",
                "ranking_factors": {
                    "expected_value": 8,
                    "risk": 15,
                    "noise": 15,
                    "rollback_quality": 15,
                    "prerequisite_satisfaction": 15,
                    "detection_value": 5,
                },
            }
        )
    return sorted(actions, key=lambda item: (-item["score"], item["id"]))


def dashboard(
    session: Path,
    *,
    objective: str | None = None,
    mode: str = "OBSERVE",
    ranking: str = "balanced",
) -> dict[str, Any]:
    session = Path(session)
    meta = _load(session / "session.json", {})
    findings_view = session_findings_dashboard(session)
    graph = None
    if (session / "graph.json").is_file():
        try:
            graph = AttackGraph.from_file(session / "graph.json")
        except (OSError, KeyError, TypeError, ValueError):
            graph = None
    findings = findings_view.get("findings") or []
    edges = graph.summary()["edges"] if graph else 0
    open_count = sum(
        str(item.get("status", "open")).lower() not in {"closed", "mitigated"} for item in findings
    )
    selected_mode = mode.upper() if mode.upper() in MODES else "OBSERVE"
    selected_ranking = ranking.lower() if ranking.lower() in RANKING_MODES else "balanced"
    events = []
    events_path = session / "events.jsonl"
    if events_path.is_file():
        for line in events_path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                events.append(event)
    open_finding = next(
        (
            item
            for item in findings
            if str(item.get("status", "open")).lower() not in {"closed", "mitigated"}
        ),
        {},
    )
    top_path = (
        graph.rank_exploit_chains(limit=1) if graph else findings_view.get("top_paths", [])[:1]
    )
    path_value = top_path[0].get("path") if top_path and isinstance(top_path[0], dict) else None
    objective_title = objective or meta.get("objective") or "Evidence-backed engagement review"
    return {
        "ok": True,
        "session": str(session),
        "engagement": {
            "id": meta.get("engagement_id") or meta.get("session_id") or session.name,
            "scope": meta.get("scope") or meta.get("target") or {},
            "mode": selected_mode,
        },
        "objective": {
            "title": objective_title,
            "progress": round((len(findings) - open_count) / len(findings) * 100)
            if findings
            else 0,
            "open_findings": open_count,
        },
        "access": {
            "identity": meta.get("username") or meta.get("identity") or "not recorded",
            "credential_context": meta.get("credential_context") or "not recorded",
        },
        "findings": {
            "count": len(findings),
            "severity": findings_view.get("severity_counts", {}),
            "items": findings,
        },
        "attack_paths": {
            "nodes": graph.summary()["nodes"] if graph else 0,
            "edges": edges,
            "top": graph.rank_exploit_chains(limit=10)
            if graph
            else findings_view.get("top_paths", []),
        },
        "health": {
            "scope": "recorded" if meta.get("scope") or meta.get("target") else "needs review",
            "evidence": "present" if findings or (session / "events.jsonl").is_file() else "empty",
            "report_ready": open_count == 0,
        },
        "recommended_next_actions": _next_actions(session, findings, edges, selected_ranking),
        "ranking": selected_ranking,
        "breadcrumbs": {
            "engagement": meta.get("engagement_id") or meta.get("session_id") or session.name,
            "objective": objective_title,
            "identity": meta.get("username") or meta.get("identity") or "not recorded",
            "finding": open_finding.get("id") or open_finding.get("title"),
            "attack_path": " -> ".join(str(item) for item in path_value) if path_value else None,
            "current_action": events[-1].get("capability") or events[-1].get("type")
            if events
            else None,
        },
    }


def missions() -> list[dict[str, Any]]:
    return [
        {
            "id": item[0],
            "title": item[1],
            "objective": item[1],
            "capabilities": list(item[2]),
        }
        for item in MISSIONS
    ]


def mission(mission_id: str) -> dict[str, Any] | None:
    return next((item for item in missions() if item["id"] == mission_id), None)


def inspect_edge(
    graph_path: Path,
    *,
    index: int | None = None,
    source: str | None = None,
    target: str | None = None,
    relation: str | None = None,
) -> dict[str, Any]:
    graph = AttackGraph.from_file(graph_path)
    edges = []
    for position, edge in enumerate(graph.edges):
        if (
            index is not None
            and position != index
            or source is not None
            and edge.source != source
            or target is not None
            and edge.target != target
            or relation is not None
            and edge.kind != relation
        ):
            continue
        profile = EXPLOIT_PROFILES.get(edge.kind, {})
        edges.append(
            {
                "index": position,
                "source": edge.source,
                "target": edge.target,
                "relation": edge.kind,
                "evidence": edge.properties,
                "exploitability": "high" if profile else "medium",
                "prerequisites": edge.properties.get(
                    "prerequisites", ["Source and target are present in saved graph evidence"]
                ),
                "risk": "R3"
                if edge.kind in {"GenericAll", "WriteDacl", "WriteOwner", "WriteGPO"}
                else "R1",
                "attack_mapping": profile.get("techniques", []),
                "expected_telemetry": ["Directory service audit events"],
                "remediation": "Remove or constrain the relationship, then verify it is absent.",
            }
        )
    return {"ok": True, "graph": str(graph_path), "count": len(edges), "edges": edges}
