"""Evidence-first, explainable UX services for the CLI and TUI."""

from __future__ import annotations

import json
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from adaf_attack.core.tooling import graph_explorer
from adaf_attack.core.ux import session_findings_dashboard


def evidence_cockpit(
    session: Path, *, start: str | None = None, limit: int = 10
) -> dict[str, Any]:
    """Combine session health, findings, graph paths, and recommended focus."""
    dashboard = session_findings_dashboard(session, limit=limit)
    graph = session / "graph.json"
    explorer = graph_explorer(graph, start=start, limit=limit) if graph.is_file() else None
    findings = dashboard.get("findings") or []
    focus = sorted(
        findings,
        key=lambda item: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
            str(item.get("severity", "unknown")).lower(), 4
        ),
    )[:3]
    return {
        "ok": True,
        "session": str(session),
        "dashboard": dashboard,
        "graph": explorer,
        "priority_focus": focus,
        "explainability": "Every path and focus item is derived from saved session evidence.",
        "offline": True,
    }


def what_if_graph(
    graph_path: Path,
    *,
    remove_relation: str | None = None,
    remove_source: str | None = None,
    remove_target: str | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    """Simulate graph evidence changes without writing or contacting a target."""
    raw = json.loads(graph_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("edges"), list):
        raise ValueError("Graph must contain an edges list")
    original_edges = raw["edges"]
    filtered: list[Any] = []
    removed: list[dict[str, Any]] = []
    for edge in original_edges:
        if not isinstance(edge, dict):
            filtered.append(edge)
            continue
        matches = (
            (remove_relation is None or edge.get("kind") == remove_relation)
            and (remove_source is None or edge.get("source") == remove_source)
            and (remove_target is None or edge.get("target") == remove_target)
        )
        (removed if matches else filtered).append(edge)
    simulated = dict(raw)
    simulated["edges"] = filtered
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="adaf-what-if-", dir=graph_path.parent, delete=False, encoding="utf-8"
    ) as handle:
        handle.write(json.dumps(simulated))
        temp = Path(handle.name)
    try:
        before = graph_explorer(graph_path, limit=limit)
        after = graph_explorer(temp, limit=limit)
    finally:
        temp.unlink(missing_ok=True)
    return {
        "ok": True,
        "graph": str(graph_path),
        "removed_edges": removed,
        "before": before["summary"],
        "after": after["summary"],
        "paths_before": before["path_count"],
        "paths_after": after["path_count"],
        "offline": True,
        "writes_target": False,
    }


def session_timeline(session: Path, *, limit: int = 100) -> dict[str, Any]:
    """Normalize audit events into a replayable engagement timeline."""
    events_path = session / "events.jsonl"
    events: list[dict[str, Any]] = []
    if events_path.is_file():
        for line in events_path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                events.append({
                    "time": item.get("ts") or item.get("time"),
                    "type": item.get("type") or item.get("event") or "event",
                    "capability": item.get("capability"),
                    "status": "error" if "error" in item else "ok",
                })
    return {"ok": True, "session": str(session), "events": events[-max(1, limit):], "count": len(events), "replayable": True}


def copilot_recommendations(session: Path) -> dict[str, Any]:
    """Produce explainable, evidence-backed next actions without executing them."""
    dashboard = session_findings_dashboard(session)
    recommendations: list[dict[str, Any]] = []
    triage = dashboard.get("triage_counts") or {}
    if triage.get("open", 0):
        recommendations.append({
            "id": "triage-open-findings",
            "action": "Review and assign open findings",
            "why": f"{triage['open']} finding(s) remain open in the session.",
            "confidence": "high",
            "command": f"adaf-attack session show --session {session}",
        })
    if dashboard.get("graph", {}).get("edges", 0):
        recommendations.append({
            "id": "rank-evidence-paths",
            "action": "Rank evidence-backed attack paths",
            "why": "The session contains graph relationships that can be analyzed offline.",
            "confidence": "high",
            "command": f"adaf-attack rank-paths --graph {session / 'graph.json'}",
        })
    if not recommendations:
        recommendations.append({
            "id": "generate-report",
            "action": "Generate the engagement report",
            "why": "No higher-priority open finding or graph action was detected.",
            "confidence": "medium",
            "command": f"adaf-attack engagement report --session {session}",
        })
    return {"ok": True, "session": str(session), "recommendations": recommendations, "execution": "suggestions-only"}


def collaboration_summary(session: Path) -> dict[str, Any]:
    """Summarize ownership and collaboration fields without exposing secrets."""
    dashboard = session_findings_dashboard(session)
    findings = dashboard.get("findings") or []
    owners = Counter(str(item.get("owner")) for item in findings if item.get("owner"))
    comments = sum(1 for item in findings if item.get("comment") or item.get("triage_note"))
    return {"ok": True, "session": str(session), "owners": dict(owners), "commented_findings": comments, "findings": findings}
