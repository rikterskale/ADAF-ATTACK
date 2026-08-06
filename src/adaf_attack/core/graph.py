"""Lightweight attack-path graph.

Nodes and edges are stored in memory. Designed to be extended later with
BloodHound-compatible export and path ranking.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


@dataclass
class Node:
    id: str
    kind: str  # User, Computer, Group, Domain, GPO, etc.
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    source: str
    target: str
    kind: str  # MemberOf, AdminTo, HasSPN, CanASREP, etc.
    properties: dict[str, Any] = field(default_factory=dict)


class AttackGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._adj: dict[str, list[Edge]] = defaultdict(list)

    def add_node(self, node_id: str, kind: str, **properties: Any) -> Node:
        if node_id in self.nodes:
            self.nodes[node_id].properties.update(properties)
            return self.nodes[node_id]
        node = Node(id=node_id, kind=kind, properties=properties)
        self.nodes[node_id] = node
        return node

    def add_edge(
        self,
        source: str,
        target: str,
        kind: str,
        **properties: Any,
    ) -> Edge:
        edge = Edge(source=source, target=target, kind=kind, properties=properties)
        self.edges.append(edge)
        self._adj[source].append(edge)
        return edge

    def neighbors(self, node_id: str, edge_kind: str | None = None) -> list[Edge]:
        edges = self._adj.get(node_id, [])
        if edge_kind is None:
            return list(edges)
        return [e for e in edges if e.kind == edge_kind]

    def nodes_of_kind(self, kind: str) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind == kind]

    def summary(self) -> dict[str, Any]:
        kind_counts: dict[str, int] = defaultdict(int)
        for n in self.nodes.values():
            kind_counts[n.kind] += 1
        edge_counts: dict[str, int] = defaultdict(int)
        for e in self.edges:
            edge_counts[e.kind] += 1
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "node_kinds": dict(kind_counts),
            "edge_kinds": dict(edge_counts),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [
                {"id": n.id, "kind": n.kind, "properties": n.properties}
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "kind": e.kind,
                    "properties": e.properties,
                }
                for e in self.edges
            ],
            "summary": self.summary(),
        }

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2))

    def find_paths(
        self,
        start: str,
        goal_kinds: Iterable[str] = ("Domain",),
        max_depth: int = 6,
    ) -> list[list[str]]:
        """Very simple BFS path finder (placeholder for real ranking)."""
        goal_kinds_set = set(goal_kinds)
        paths: list[list[str]] = []
        queue: list[tuple[str, list[str]]] = [(start, [start])]
        visited: set[str] = set()

        while queue:
            current, path = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            node = self.nodes.get(current)
            if node and node.kind in goal_kinds_set and len(path) > 1:
                paths.append(path)
                continue

            if len(path) >= max_depth:
                continue

            for edge in self.neighbors(current):
                if edge.target not in path:
                    queue.append((edge.target, path + [edge.target]))

        return paths
