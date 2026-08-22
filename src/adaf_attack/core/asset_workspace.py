"""Read-only asset-centric workspace assembled from saved engagement evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adaf_attack.core.access_context import session_access_context
from adaf_attack.core.graph import AttackGraph


def _load_findings(session: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads((session / "findings.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    values = payload.get("findings", []) if isinstance(payload, dict) else payload
    return [item for item in values if isinstance(item, dict)] if isinstance(values, list) else []


def _matches(value: Any, asset: str) -> bool:
    return asset.casefold() in str(value).casefold()


def build_asset_workspace(session: Path, asset: str) -> dict[str, Any]:
    """Return findings, graph relationships, actions, and safe access context for an asset."""
    session = Path(session)
    asset = asset.strip()
    if not asset:
        raise ValueError("Asset identifier cannot be empty")
    graph: AttackGraph | None = None
    graph_path = session / "graph.json"
    if graph_path.is_file():
        try:
            graph = AttackGraph.from_file(graph_path)
        except (OSError, KeyError, TypeError, ValueError):
            graph = None
    nodes = []
    relationships = []
    if graph:
        matched_ids = {
            node.id
            for node in graph.nodes.values()
            if _matches(node.id, asset)
            or any(_matches(value, asset) for value in node.properties.values())
        }
        nodes = [
            {"id": node.id, "kind": node.kind, "properties": node.properties}
            for node in graph.nodes.values()
            if node.id in matched_ids
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
    findings = [finding for finding in _load_findings(session) if _matches(finding, asset)]
    actions = []
    events_path = session / "events.jsonl"
    if events_path.is_file():
        for line in events_path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and _matches(event, asset):
                actions.append(
                    {
                        "event": event.get("type"),
                        "capability": event.get("capability"),
                        "identity": event.get("username") or event.get("identity"),
                    }
                )
    return {
        "ok": True,
        "session": str(session),
        "asset": asset,
        "nodes": nodes,
        "relationships": relationships,
        "findings": findings,
        "actions": actions,
        "access": session_access_context(session),
        "summary": {
            "nodes": len(nodes),
            "relationships": len(relationships),
            "findings": len(findings),
            "actions": len(actions),
        },
    }
