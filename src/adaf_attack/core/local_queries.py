"""Deterministic natural-language queries over local engagement evidence."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from adaf_attack.core.graph import AttackGraph

_PATH_QUERY = re.compile(r"(?:show\s+)?(?:every\s+)?paths?\s+from\s+(.+?)\s+to\s+(.+?)[?.]*$", re.I)
_FINDING_QUERY = re.compile(r"which\s+findings?\s+depend\s+on\s+(.+?)[?.]*$", re.I)


def query_local_evidence(session: Path, question: str, *, limit: int = 25) -> dict[str, Any]:
    """Answer supported local graph/finding questions without contacting a target."""
    question = question.strip()
    path_match = _PATH_QUERY.fullmatch(question)
    if path_match:
        return _query_paths(session, path_match.group(1), path_match.group(2), limit=limit)
    finding_match = _FINDING_QUERY.fullmatch(question)
    if finding_match:
        return _query_findings(session, finding_match.group(1), limit=limit)
    return {
        "ok": False,
        "query": question,
        "error": "Unsupported local query",
        "supported_queries": [
            "show every path from <identity> to <target>",
            "which findings depend on <identity>",
        ],
        "offline": True,
    }


def _load_graph(session: Path) -> AttackGraph:
    graph_path = Path(session) / "graph.json"
    if not graph_path.is_file():
        raise ValueError("Session has no graph.json evidence")
    return AttackGraph.from_file(graph_path)


def _resolve_starts(graph: AttackGraph, text: str) -> list[str]:
    lowered = text.strip().lower()
    if "compromised" in lowered and "user" in lowered:
        candidates = [
            node.id
            for node in graph.nodes_of_kind("User")
            if node.properties.get("compromised", True)
        ]
        return sorted(candidates)
    resolved = graph.find_node(text)
    return [resolved] if resolved else []


def _resolve_goals(graph: AttackGraph, text: str) -> set[str]:
    lowered = text.strip().lower()
    if "domain admin" in lowered or "tier 0" in lowered:
        return {
            node.id
            for node in graph.nodes.values()
            if node.kind == "Group"
            and ("DOMAIN ADMINS" in node.id.upper() or node.properties.get("admin_count"))
        }
    resolved = graph.find_node(text)
    return {resolved} if resolved else set()


def _query_paths(session: Path, start_text: str, goal_text: str, *, limit: int) -> dict[str, Any]:
    graph = _load_graph(session)
    starts = _resolve_starts(graph, start_text)
    goals = _resolve_goals(graph, goal_text)
    paths: list[dict[str, Any]] = []
    for start in starts:
        queue: list[tuple[str, list[str], list[str]]] = [(start, [start], [])]
        while queue and len(paths) < limit:
            current, nodes, edges = queue.pop(0)
            if current in goals and len(nodes) > 1:
                paths.append(
                    {
                        "path": nodes,
                        "edges": edges,
                        "length": len(edges),
                        "start": start,
                        "end": current,
                    }
                )
                continue
            if len(edges) >= 8:
                continue
            for edge in sorted(graph.neighbors(current), key=lambda item: (item.target, item.kind)):
                if edge.target not in nodes:
                    queue.append((edge.target, [*nodes, edge.target], [*edges, edge.kind]))
    return {
        "ok": True,
        "query_type": "paths",
        "start": start_text,
        "goal": goal_text,
        "paths": paths,
        "count": len(paths),
        "offline": True,
    }


def _query_findings(session: Path, subject: str, *, limit: int) -> dict[str, Any]:
    try:
        payload = json.loads((Path(session) / "findings.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = {}
    values = payload.get("findings") if isinstance(payload, dict) else []
    matches = []
    for finding in values if isinstance(values, list) else []:
        if not isinstance(finding, dict):
            continue
        haystack = json.dumps(finding, sort_keys=True, default=str).lower()
        if subject.lower().strip() in haystack:
            matches.append(finding)
    return {
        "ok": True,
        "query_type": "finding-dependencies",
        "subject": subject,
        "findings": matches[:limit],
        "count": min(len(matches), limit),
        "offline": True,
    }
