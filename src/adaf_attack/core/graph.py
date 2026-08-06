"""Lightweight attack-path graph with basic ranking."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# Edge weights for simple path scoring (lower = more interesting / shorter effort)
EDGE_WEIGHTS: dict[str, float] = {
    "AdminTo": 1.0,
    "HasSession": 1.2,
    "ForceChangePassword": 1.5,
    "GenericAll": 1.0,
    "GenericWrite": 1.3,
    "WriteDacl": 1.3,
    "WriteOwner": 1.3,
    "AddMember": 1.4,
    "CanASREP": 2.0,
    "HasSPN": 2.5,
    "MemberOf": 3.0,
    "TrustedBy": 4.0,
    "Default": 5.0,
}


@dataclass
class Node:
    id: str
    kind: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    source: str
    target: str
    kind: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class RankedPath:
    nodes: list[str]
    edges: list[str]
    score: float
    length: int


class AttackGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._adj: dict[str, list[Edge]] = defaultdict(list)
        self._dn_index: dict[str, str] = {}  # DN -> node_id

    def add_node(self, node_id: str, kind: str, **properties: Any) -> Node:
        if node_id in self.nodes:
            self.nodes[node_id].properties.update(properties)
            node = self.nodes[node_id]
        else:
            node = Node(id=node_id, kind=kind, properties=properties)
            self.nodes[node_id] = node

        dn = properties.get("dn") or node.properties.get("dn")
        if dn:
            self._dn_index[str(dn).upper()] = node_id
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

    def resolve_dn_edges(self) -> int:
        """Rewrite GROUPDN@... MemberOf targets to real GROUP@... node IDs."""
        resolved = 0
        new_edges: list[Edge] = []
        self._adj = defaultdict(list)

        for edge in self.edges:
            target = edge.target
            if target.startswith("GROUPDN@"):
                dn = target[len("GROUPDN@") :].upper()
                real_id = self._dn_index.get(dn)
                if real_id:
                    target = real_id
                    resolved += 1
                else:
                    # keep unresolved for visibility
                    pass
            new_edge = Edge(
                source=edge.source,
                target=target,
                kind=edge.kind,
                properties=edge.properties,
            )
            new_edges.append(new_edge)
            self._adj[new_edge.source].append(new_edge)

        self.edges = new_edges
        return resolved

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

    def _edge_weight(self, kind: str) -> float:
        return EDGE_WEIGHTS.get(kind, EDGE_WEIGHTS["Default"])

    def rank_paths(
        self,
        start: str,
        goal_kinds: Iterable[str] = ("Group", "Domain"),
        max_depth: int = 5,
        limit: int = 20,
    ) -> list[RankedPath]:
        """BFS with cumulative edge-weight scoring. Lower score = more interesting."""
        goal_kinds_set = set(goal_kinds)
        found: list[RankedPath] = []
        queue: list[tuple[str, list[str], list[str], float]] = [
            (start, [start], [], 0.0)
        ]
        visited_depth: dict[str, int] = {start: 0}

        while queue:
            current, path, edge_kinds, score = queue.pop(0)
            node = self.nodes.get(current)

            if node and node.kind in goal_kinds_set and len(path) > 1:
                # Prefer Domain Admins / high-value groups
                bonus = 0.0
                name = (node.properties.get("sam") or "").upper()
                if name in {"DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS"}:
                    bonus = -2.0
                found.append(
                    RankedPath(
                        nodes=path,
                        edges=edge_kinds,
                        score=score + bonus,
                        length=len(path) - 1,
                    )
                )
                continue

            if len(path) >= max_depth:
                continue

            for edge in self.neighbors(current):
                nxt = edge.target
                if nxt in path:
                    continue
                depth = len(path)
                if nxt in visited_depth and visited_depth[nxt] < depth:
                    continue
                visited_depth[nxt] = depth
                w = self._edge_weight(edge.kind)
                queue.append(
                    (nxt, path + [nxt], edge_kinds + [edge.kind], score + w)
                )

        found.sort(key=lambda p: (p.score, p.length))
        return found[:limit]

    def interesting_summary(self, limit: int = 15) -> dict[str, Any]:
        """High-signal overview used by CLI and TUI."""
        asrep = [
            n.id for n in self.nodes.values()
            if n.kind == "User" and n.properties.get("dont_req_preauth")
        ]
        spn_users = [
            n.id for n in self.nodes.values()
            if n.kind == "User" and n.properties.get("spns")
        ]
        admin_groups = [
            n.id for n in self.nodes.values()
            if n.kind == "Group" and n.properties.get("admin_count")
        ]

        # Sample paths from a few high-value starting users
        sample_paths: list[dict[str, Any]] = []
        for user in self.nodes_of_kind("User")[:30]:
            paths = self.rank_paths(user.id, goal_kinds=("Group", "Domain"), limit=3)
            for p in paths:
                sample_paths.append(
                    {
                        "start": user.id,
                        "path": p.nodes,
                        "edges": p.edges,
                        "score": round(p.score, 2),
                        "length": p.length,
                    }
                )
        sample_paths.sort(key=lambda x: x["score"])

        return {
            "asrep_roastable": asrep[:50],
            "kerberoastable": spn_users[:50],
            "admin_groups": admin_groups,
            "top_paths": sample_paths[:limit],
            "graph": self.summary(),
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
            "interesting": self.interesting_summary(),
        }

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2, default=str))
