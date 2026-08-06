"""BloodHound CE-friendly export from AttackGraph."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adaf_attack.core.graph import AttackGraph

# Map our kinds → BloodHound labels
KIND_MAP = {
    "User": "User",
    "Computer": "Computer",
    "Group": "Group",
    "Domain": "Domain",
    "CA": "EnterpriseCA",
    "CertTemplate": "CertificateTemplate",
}

# Map our edges → BH relationship names where possible
EDGE_MAP = {
    "MemberOf": "MemberOf",
    "AdminTo": "AdminTo",
    "HasSession": "HasSession",
    "TrustedBy": "TrustedBy",
    "SameForestTrust": "SameForestTrust",
    "ExternalTrust": "ExternalTrust",
    "GenericAll": "GenericAll",
    "GenericWrite": "GenericWrite",
    "ForceChangePassword": "ForceChangePassword",
    "AddMember": "AddMember",
    "HasSPN": "HasSPN",
    "CanASREP": "CanASREP",
    "ESC1Candidate": "ESC1Candidate",
}


def _node_properties(node: Any) -> dict[str, Any]:
    props = dict(node.properties)
    # BH-ish conventional fields
    if "sam" in props and "name" not in props:
        props["name"] = props["sam"]
    if "dn" in props:
        props["distinguishedname"] = props["dn"]
    props["domain"] = props.get("domain") or _domain_from_id(node.id)
    return props


def _domain_from_id(node_id: str) -> str:
    # USER@SAM@DOMAIN.COM → DOMAIN.COM
    parts = node_id.split("@")
    if len(parts) >= 3:
        return parts[-1]
    if len(parts) == 2 and parts[0] == "DOMAIN":
        return parts[1]
    return ""


def export_bloodhound(graph: AttackGraph, domain: str | None = None) -> dict[str, Any]:
    """Build a BloodHound CE-oriented graph document."""
    nodes = []
    for n in graph.nodes.values():
        label = KIND_MAP.get(n.kind, n.kind)
        nodes.append(
            {
                "id": n.id,
                "kinds": [label],
                "label": label,
                "properties": _node_properties(n),
            }
        )

    edges = []
    for e in graph.edges:
        # Skip self-loop signal edges from BH classic pathing if desired;
        # keep them as custom relationships for visibility.
        rel = EDGE_MAP.get(e.kind, e.kind)
        edges.append(
            {
                "start": {"value": e.source},
                "end": {"value": e.target},
                "kind": rel,
                "properties": dict(e.properties),
            }
        )

    meta = {
        "source": "adaf-attack",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "summary": graph.summary(),
    }

    return {
        "meta": meta,
        "graph": {
            "nodes": nodes,
            "edges": edges,
        },
        # Flat convenience form some tools accept
        "nodes": nodes,
        "edges": [
            {
                "source": e["start"]["value"],
                "target": e["end"]["value"],
                "label": e["kind"],
                "properties": e["properties"],
            }
            for e in edges
        ],
    }


def save_bloodhound(graph: AttackGraph, path: Path, domain: str | None = None) -> Path:
    doc = export_bloodhound(graph, domain=domain)
    path.write_text(json.dumps(doc, indent=2, default=str))
    return path
