"""Read-only domain and forest workspace assembled from saved evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adaf_attack.core.asset_workspace import _load_findings, _matches
from adaf_attack.core.graph import HIGH_VALUE_GROUPS, AttackGraph


def _load_meta(session: Path) -> dict[str, Any]:
    try:
        value = json.loads((session / "session.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def build_domain_workspace(session: Path) -> dict[str, Any]:
    """Return domain/forest posture, trust relationships, and evidence health."""
    session = Path(session)
    meta = _load_meta(session)
    graph: AttackGraph | None = None
    graph_path = session / "graph.json"
    if graph_path.is_file():
        try:
            graph = AttackGraph.from_file(graph_path)
        except (OSError, KeyError, TypeError, ValueError):
            graph = None
    domains: list[dict[str, Any]] = []
    forests: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    trusts: list[dict[str, Any]] = []
    tier0: list[str] = []
    if graph:
        for node in graph.nodes.values():
            record = {"id": node.id, "kind": node.kind, "properties": node.properties}
            if node.kind == "Domain" or "DOMAIN@" in node.id:
                domains.append(record)
            if node.kind == "Forest" or "forest" in node.properties:
                forests.append(record)
            if node.kind in {"Computer", "User", "Group"}:
                assets.append(record)
            if node.kind == "Group" and any(
                label in node.id.upper() for label in HIGH_VALUE_GROUPS
            ):
                tier0.append(node.id)
        trusts = [
            {
                "source": edge.source,
                "target": edge.target,
                "relation": edge.kind,
                "properties": edge.properties,
            }
            for edge in graph.edges
            if edge.kind in {"TrustedBy", "Trusts", "ForestTrust"}
        ]
    scope = meta.get("scope") or meta.get("target") or "not recorded"
    findings = [
        finding
        for finding in _load_findings(session)
        if _matches(finding, str(scope)) or any(_matches(finding, item["id"]) for item in domains)
    ]
    return {
        "ok": True,
        "session": str(session),
        "engagement": meta.get("engagement_id") or meta.get("session_id") or session.name,
        "scope": scope,
        "domains": domains,
        "forests": forests,
        "assets": assets,
        "trusts": trusts,
        "tier0": tier0,
        "findings": findings,
        "health": {
            "scope": "recorded" if scope != "not recorded" else "needs review",
            "graph": "present" if graph else "missing or unreadable",
            "evidence": "present" if findings or (session / "events.jsonl").is_file() else "empty",
        },
        "summary": {
            "domains": len(domains),
            "forests": len(forests),
            "assets": len(assets),
            "trusts": len(trusts),
            "tier0": len(tier0),
            "findings": len(findings),
        },
    }
