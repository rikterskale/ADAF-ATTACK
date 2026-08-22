"""Read-only identity-centric workspace assembled from saved engagement evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from adaf_attack.core.access_context import session_access_context
from adaf_attack.core.asset_workspace import _load_findings, _matches
from adaf_attack.core.graph import AttackGraph


def build_identity_workspace(session: Path, identity: str) -> dict[str, Any]:
    """Return identity relationships, reachable assets, findings, and safe actions."""
    session = Path(session)
    identity = identity.strip()
    if not identity:
        raise ValueError("Identity identifier cannot be empty")
    graph: AttackGraph | None = None
    graph_path = session / "graph.json"
    if graph_path.is_file():
        try:
            graph = AttackGraph.from_file(graph_path)
        except (OSError, KeyError, TypeError, ValueError):
            graph = None
    matched_ids: set[str] = set()
    nodes: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    reachable_assets: list[dict[str, Any]] = []
    if graph:
        matched_ids = {
            node.id
            for node in graph.nodes.values()
            if _matches(node.id, identity)
            or any(_matches(value, identity) for value in node.properties.values())
        }
        nodes = [
            {"id": node.id, "kind": node.kind, "properties": node.properties}
            for node in graph.nodes.values()
            if node.id in matched_ids
        ]
        connected_ids = {
            edge.target if edge.source in matched_ids else edge.source
            for edge in graph.edges
            if edge.source in matched_ids or edge.target in matched_ids
        }
        reachable_assets = [
            {"id": node.id, "kind": node.kind, "properties": node.properties}
            for node in graph.nodes.values()
            if node.id in connected_ids
            and node.id not in matched_ids
            and node.kind in {"Computer", "Domain", "User", "Group"}
        ]
        relationships = [
            {
                "source": edge.source,
                "target": edge.target,
                "relation": edge.kind,
                "properties": edge.properties,
            }
            for edge in graph.edges
            if edge.source in matched_ids or edge.target in matched_ids
        ]
    findings = [finding for finding in _load_findings(session) if _matches(finding, identity)]
    access = session_access_context(session)
    actions = [
        action
        for action in access["actions"]
        if str(action.get("identity") or "").casefold() == identity.casefold()
    ]
    identities = [
        item
        for item in access["identities"]
        if str(item["identity"]).casefold() == identity.casefold()
    ]
    lifecycle = [item for item in access["credential_lifecycle"] if identity in item["identities"]]
    return {
        "ok": True,
        "session": str(session),
        "identity": identity,
        "nodes": nodes,
        "relationships": relationships,
        "reachable_assets": reachable_assets,
        "findings": findings,
        "actions": actions,
        "identities": identities,
        "credential_lifecycle": lifecycle,
        "summary": {
            "nodes": len(nodes),
            "relationships": len(relationships),
            "reachable_assets": len(reachable_assets),
            "findings": len(findings),
            "actions": len(actions),
        },
    }
