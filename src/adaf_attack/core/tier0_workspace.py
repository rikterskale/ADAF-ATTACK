"""Read-only Tier-0 workspace assembled from saved graph and finding evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from adaf_attack.core.asset_workspace import _load_findings, _matches
from adaf_attack.core.graph import HIGH_VALUE_GROUPS, AttackGraph


def build_tier0_workspace(session: Path) -> dict[str, Any]:
    """Return privileged nodes, controlling relationships, paths, and findings."""
    session = Path(session)
    graph: AttackGraph | None = None
    graph_path = session / "graph.json"
    if graph_path.is_file():
        try:
            graph = AttackGraph.from_file(graph_path)
        except (OSError, KeyError, TypeError, ValueError):
            graph = None
    tier0_ids: set[str] = set()
    nodes: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    paths: list[dict[str, Any]] = []
    if graph:
        tier0_ids = {
            node.id
            for node in graph.nodes.values()
            if node.kind == "Group" and any(label in node.id.upper() for label in HIGH_VALUE_GROUPS)
        }
        nodes = [
            {"id": node.id, "kind": node.kind, "properties": node.properties}
            for node in graph.nodes.values()
            if node.id in tier0_ids
        ]
        relationships = [
            {
                "source": edge.source,
                "target": edge.target,
                "relation": edge.kind,
                "properties": edge.properties,
            }
            for edge in graph.edges
            if edge.target in tier0_ids or edge.source in tier0_ids
        ]
        paths = [
            path
            for path in graph.rank_exploit_chains(limit=25)
            if any(str(node) in tier0_ids for node in path.get("path", []))
        ]
    findings = [
        finding
        for finding in _load_findings(session)
        if _matches(finding, "tier 0") or any(_matches(finding, node_id) for node_id in tier0_ids)
    ]
    return {
        "ok": True,
        "session": str(session),
        "tier0_nodes": nodes,
        "relationships": relationships,
        "paths": paths,
        "findings": findings,
        "summary": {
            "nodes": len(nodes),
            "relationships": len(relationships),
            "paths": len(paths),
            "findings": len(findings),
        },
    }
