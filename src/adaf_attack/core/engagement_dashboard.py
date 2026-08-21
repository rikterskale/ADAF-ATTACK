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


def _next_actions(
    session: Path, findings: list[dict[str, Any]], edges: int
) -> list[dict[str, Any]]:
    actions = []
    for finding in findings:
        if str(finding.get("status", "open")).lower() in {"closed", "mitigated"}:
            continue
        severity = str(finding.get("severity", "unknown")).lower()
        confidence = str(finding.get("confidence", "unknown")).lower()
        score = {"critical": 100, "high": 80, "medium": 55, "low": 30}.get(severity, 15)
        score += {"confirmed": 20, "high": 15, "medium": 8}.get(confidence, 0)
        actions.append(
            {
                "id": f"finding:{finding.get('id') or finding.get('title')}",
                "action": "Validate and triage finding",
                "why": "An open finding still needs evidence or a decision.",
                "score": score,
                "risk": "R1",
            }
        )
    if edges:
        actions.append(
            {
                "id": "rank-attack-paths",
                "action": "Rank evidence-backed attack paths",
                "why": "The session contains graph relationships that can be inspected offline.",
                "score": 70,
                "risk": "R1",
            }
        )
    if not actions:
        actions.append(
            {
                "id": "generate-report",
                "action": "Generate engagement deliverables",
                "why": "No open action is blocking reporting.",
                "score": 20,
                "risk": "R1",
            }
        )
    return sorted(actions, key=lambda item: (-item["score"], item["id"]))


def dashboard(
    session: Path, *, objective: str | None = None, mode: str = "OBSERVE"
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
    return {
        "ok": True,
        "session": str(session),
        "engagement": {
            "id": meta.get("engagement_id") or meta.get("session_id") or session.name,
            "scope": meta.get("scope") or meta.get("target") or {},
            "mode": selected_mode,
        },
        "objective": {
            "title": objective or meta.get("objective") or "Evidence-backed engagement review",
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
        "recommended_next_actions": _next_actions(session, findings, edges),
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
                "risk": "R3"
                if edge.kind in {"GenericAll", "WriteDacl", "WriteOwner", "WriteGPO"}
                else "R1",
                "attack_mapping": profile.get("techniques", []),
                "expected_telemetry": ["Directory service audit events"],
                "remediation": "Remove or constrain the relationship, then verify it is absent.",
            }
        )
    return {"ok": True, "graph": str(graph_path), "count": len(edges), "edges": edges}
