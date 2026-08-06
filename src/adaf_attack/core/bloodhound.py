"""BloodHound CE-friendly export (JSON + zip)."""

from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adaf_attack.core.graph import AttackGraph

KIND_MAP = {
    "User": "User",
    "Computer": "Computer",
    "Group": "Group",
    "Domain": "Domain",
    "CA": "EnterpriseCA",
    "CertTemplate": "CertificateTemplate",
    "Container": "Container",
    "Base": "Base",
}

EDGE_MAP = {
    "MemberOf": "MemberOf",
    "AdminTo": "AdminTo",
    "HasSession": "HasSession",
    "TrustedBy": "TrustedBy",
    "SameForestTrust": "SameForestTrust",
    "ExternalTrust": "ExternalTrust",
    "GenericAll": "GenericAll",
    "GenericWrite": "GenericWrite",
    "WriteDacl": "WriteDacl",
    "WriteOwner": "WriteOwner",
    "ForceChangePassword": "ForceChangePassword",
    "AddMember": "AddMember",
    "AllExtendedRights": "AllExtendedRights",
    "GetChanges": "GetChanges",
    "GetChangesAll": "GetChangesAll",
    "DCSync": "DCSync",
    "HasSPN": "HasSPN",
    "CanASREP": "CanASREP",
    "ESC1Candidate": "ESC1Candidate",
    "ESC1Enrollable": "ESC1Enrollable",
    "Enroll": "Enroll",
    "AutoEnroll": "AutoEnroll",
    "GMSAPasswordReadable": "GMSAPasswordReadable",
    "LAPSReadable": "LAPSReadable",
}


def _domain_from_id(node_id: str) -> str:
    parts = node_id.split("@")
    if len(parts) >= 3:
        return parts[-1]
    if len(parts) == 2 and parts[0] == "DOMAIN":
        return parts[1]
    return ""


def _node_properties(node: Any) -> dict[str, Any]:
    props = dict(node.properties)
    if "sam" in props and "name" not in props:
        props["name"] = props["sam"]
    if "dn" in props:
        props["distinguishedname"] = props["dn"]
    props["domain"] = props.get("domain") or _domain_from_id(node.id)
    return props


def export_bloodhound(graph: AttackGraph, domain: str | None = None) -> dict[str, Any]:
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
        "graph": {"nodes": nodes, "edges": edges},
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


def save_bloodhound_zip(
    graph: AttackGraph,
    zip_path: Path,
    domain: str | None = None,
) -> Path:
    """Write a zip suitable for BloodHound CE file ingest.

    Contains:
      - bloodhound.json (full CE-oriented document)
      - nodes.json / edges.json (split arrays)
      - meta.json
    """
    doc = export_bloodhound(graph, domain=domain)
    zip_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bloodhound.json", json.dumps(doc, indent=2, default=str))
        zf.writestr("nodes.json", json.dumps(doc["nodes"], indent=2, default=str))
        zf.writestr("edges.json", json.dumps(doc["edges"], indent=2, default=str))
        zf.writestr("meta.json", json.dumps(doc["meta"], indent=2, default=str))

    return zip_path
