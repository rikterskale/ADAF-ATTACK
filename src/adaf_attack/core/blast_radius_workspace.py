"""Read-only blast-radius view over saved attack-graph evidence."""

from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Any

from adaf_attack.core.asset_workspace import _load_findings, _matches
from adaf_attack.core.graph import AttackGraph


def build_blast_radius_workspace(
    session: Path, principal: str, *, max_depth: int = 6
) -> dict[str, Any]:
    """Return reachable nodes, high-value impacts, and related findings offline."""
    session = Path(session)
    principal = principal.strip()
    if not principal:
        raise ValueError("Principal identifier cannot be empty")
    graph_path = session / "graph.json"
    if not graph_path.is_file():
        return {
            "ok": True,
            "session": str(session),
            "principal": principal,
            "reachable_nodes": 0,
            "impacts": [],
            "findings": [],
            "summary": {"reachable_nodes": 0, "impacts": 0, "findings": 0},
        }
    try:
        graph = AttackGraph.from_file(graph_path)
    except (OSError, KeyError, TypeError, ValueError):
        return {
            "ok": True,
            "session": str(session),
            "principal": principal,
            "reachable_nodes": 0,
            "impacts": [],
            "findings": [],
            "summary": {"reachable_nodes": 0, "impacts": 0, "findings": 0},
        }
    start = graph.find_node(principal)
    if not start:
        raise ValueError(f"Principal not found in graph: {principal}")
    queue: deque[tuple[str, list[str]]] = deque([(start, [start])])
    seen = {start}
    impacts: list[dict[str, Any]] = []
    while queue:
        current, path = queue.popleft()
        for edge in graph.neighbors(current):
            next_path = path + ([] if edge.target == current else [edge.target])
            if edge.target in seen and edge.target != current:
                continue
            if edge.target != current:
                seen.add(edge.target)
            target_node = graph.nodes.get(edge.target)
            if target_node and (
                target_node.properties.get("admin_count") or "DOMAIN ADMINS" in edge.target
            ):
                impacts.append({"target": edge.target, "path": next_path, "via": edge.kind})
            if edge.target != current and len(next_path) < max_depth:
                queue.append((edge.target, next_path))
    findings = [finding for finding in _load_findings(session) if _matches(finding, principal)]
    return {
        "ok": True,
        "session": str(session),
        "principal": start,
        "reachable_nodes": len(seen),
        "impacts": impacts,
        "findings": findings,
        "summary": {
            "reachable_nodes": len(seen),
            "impacts": len(impacts),
            "findings": len(findings),
        },
    }
