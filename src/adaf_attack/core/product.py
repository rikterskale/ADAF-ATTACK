"""Polished product-level views over the existing evidence workflows."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from adaf_attack.core.standout_ux import evidence_cockpit, session_timeline
from adaf_attack.core.ux import session_findings_dashboard
from adaf_attack.core.workflows import PROFILES


def command_center(session: Path) -> dict[str, Any]:
    """Return the single-screen product overview for an engagement."""
    cockpit = evidence_cockpit(session)
    timeline = session_timeline(session, limit=20)
    dashboard = cockpit["dashboard"]
    return {
        "ok": True,
        "session": str(session),
        "headline": f"{dashboard.get('finding_count', 0)} evidence-backed finding(s)",
        "cockpit": cockpit,
        "timeline": timeline,
        "deliverables": deliverables_manifest(session),
        "mode": "review-and-report",
    }


def evidence_impact_map(session: Path) -> dict[str, Any]:
    """Map findings to evidence, graph paths, assets, and business impact."""
    dashboard = session_findings_dashboard(session)
    findings = dashboard.get("findings") or []
    graph = (
        json.loads((session / "graph.json").read_text(encoding="utf-8"))
        if (session / "graph.json").is_file()
        else {}
    )
    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    assets = sorted(
        {str(node.get("id")) for node in nodes if isinstance(node, dict) and node.get("id")}
    )
    mapping = []
    for finding in findings:
        mapping.append(
            {
                "finding_id": finding.get("id"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "evidence": finding.get("evidence")
                or finding.get("category")
                or "session artifact",
                "affected_assets": assets[:10],
                "impact": "Potential privilege, credential, or control-path exposure; validate before action.",
            }
        )
    return {
        "ok": True,
        "session": str(session),
        "map": mapping,
        "count": len(mapping),
        "offline": True,
    }


def zero_noise_investigation(session: Path) -> dict[str, Any]:
    """Describe the read-only evidence investigation surface."""
    dashboard = session_findings_dashboard(session)
    artifacts = sorted(path.name for path in session.glob("*") if path.is_file())
    return {
        "ok": True,
        "session": str(session),
        "artifacts": artifacts,
        "finding_count": dashboard.get("finding_count", 0),
        "network_contact": False,
        "target_mutation": False,
        "available_actions": [
            "filter findings",
            "rank paths",
            "compare sessions",
            "generate reports",
        ],
    }


def executive_story(session: Path) -> dict[str, Any]:
    """Create a concise executive narrative from technical evidence."""
    dashboard = session_findings_dashboard(session)
    severity = dashboard.get("severity_counts") or {}
    top = (dashboard.get("findings") or [])[:5]
    highest = next(
        (level for level in ("critical", "high", "medium", "low") if severity.get(level)), "none"
    )
    narrative = (
        f"The assessment produced {dashboard.get('finding_count', 0)} finding(s). "
        f"The highest observed severity was {highest}. "
        "Priority should be given to validating the highest-confidence paths and assigning owners before remediation verification."
    )
    return {
        "ok": True,
        "session": str(session),
        "narrative": narrative,
        "risk_posture": {"highest_severity": highest, "severity_counts": severity},
        "priority_decisions": top,
        "audience": "executive",
    }


def confidence_report(session: Path) -> dict[str, Any]:
    """Summarize confidence quality and identify weakly supported findings."""
    payload = (
        json.loads((session / "findings.json").read_text(encoding="utf-8"))
        if (session / "findings.json").is_file()
        else {}
    )
    findings = payload.get("findings", []) if isinstance(payload, dict) else []
    counts: Counter[str] = Counter()
    review: list[str] = []
    for finding in findings if isinstance(findings, list) else []:
        if not isinstance(finding, dict):
            continue
        value = str(
            finding.get("confidence") or ("medium" if finding.get("evidence") else "unknown")
        ).lower()
        counts[value] += 1
        if value in {"unknown", "low"}:
            review.append(str(finding.get("id") or finding.get("title") or "finding"))
    return {
        "ok": True,
        "session": str(session),
        "confidence_counts": dict(counts),
        "needs_more_evidence": review,
        "quality": "strong" if not review else "review-needed",
    }


def deliverables_manifest(session: Path) -> dict[str, Any]:
    """List available and expected client deliverables without generating files."""
    reports = session / "reports"
    files = (
        sorted(str(path.relative_to(session)) for path in reports.glob("*") if path.is_file())
        if reports.is_dir()
        else []
    )
    return {
        "session": str(session),
        "available": files,
        "expected": [
            "reports/executive.html",
            "reports/technical.html",
            "reports/remediation.html",
            "redacted-evidence.zip",
        ],
        "ready": bool(files),
        "generate_command": f"adaf-attack engagement report --session {session}",
    }


def product_templates() -> list[dict[str, Any]]:
    """Return polished, repeatable assessment templates."""
    return [{"id": key, **value} for key, value in sorted(PROFILES.items())]
