"""Read-only campaign analysis: blast radius and continuous purple feedback."""

from __future__ import annotations

import json
from collections import deque
from typing import Any

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def _load_graph(session: Session, graph: AttackGraph) -> AttackGraph:
    if graph.nodes:
        return graph
    path = session.path("graph.json")
    if not path.is_file():
        raise RuntimeError("No graph available in the session")
    return AttackGraph.from_file(path)


@register_capability(id="blast-radius", summary="Calculate reachable high-value impact from a graph principal", category="analysis", tags=("blast-radius", "impact", "graph"))
class BlastRadius:
    def run(self, target: Target, session: Session, graph: AttackGraph, **kwargs: Any) -> dict[str, Any]:
        graph = _load_graph(session, graph)
        start = kwargs.get("start") or kwargs.get("sam")
        if not start:
            raise RuntimeError("blast-radius requires --start or --sam")
        node = graph.find_node(str(start))
        if not node:
            raise RuntimeError(f"Principal not found in graph: {start}")
        queue: deque[tuple[str, list[str], float]] = deque([(node, [node], 1.0)])
        seen = {node}
        impacts: list[dict[str, Any]] = []
        while queue:
            current, path, confidence = queue.popleft()
            for edge in graph.neighbors(current):
                next_path = path + ([] if edge.target == current else [edge.target])
                if edge.target in seen and edge.target != current:
                    continue
                if edge.target != current:
                    seen.add(edge.target)
                target_node = graph.nodes.get(edge.target)
                if target_node and (target_node.properties.get("admin_count") or "DOMAIN ADMINS" in edge.target):
                    impacts.append({"target": edge.target, "path": next_path, "via": edge.kind, "confidence": round(confidence, 2)})
                if len(next_path) < int(kwargs.get("max_depth") or 6):
                    queue.append((edge.target, next_path, confidence * 0.9))
        result = {"principal": node, "reachable_nodes": len(seen), "high_value_impacts": impacts, "confidence": "evidence-backed" if impacts else "no high-value path observed"}
        session.path("blast-radius.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        session.log("blast-radius.complete", principal=node, impacts=len(impacts))
        return result


@register_capability(id="purple-feedback", summary="Generate updated detection hypotheses from session events", category="export", tags=("purple-team", "detection", "timeline"))
class PurpleFeedback:
    def run(self, target: Target, session: Session, graph: AttackGraph, **kwargs: Any) -> dict[str, Any]:
        hypotheses = {
            "shadow-creds.complete": "Monitor KeyCredentialLink attribute modifications and certificate-based Kerberos authentication.",
            "rbcd.complete": "Monitor msDS-AllowedToActOnBehalfOfOtherIdentity changes and S4U ticket requests.",
            "pkinit-auth.complete": "Monitor PKINIT AS-REQ activity and unexpected certificate mappings.",
            "kerberoast.complete": "Monitor unusually broad service-ticket requests from one principal.",
        }
        events: list[dict[str, Any]] = []
        event_path = session.path("events.jsonl")
        if event_path.exists():
            for line in event_path.read_text(encoding="utf-8").splitlines():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        detections = [
            {"event": event["type"], "hypothesis": hypotheses[event["type"]], "timestamp": event.get("ts")}
            for event in events
            if event.get("type") in hypotheses
        ]
        result = {"session": session.session_id, "detections": detections, "timeline": events, "count": len(detections)}
        session.path("purple-feedback.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        session.log("purple-feedback.complete", count=len(detections))
        return result
