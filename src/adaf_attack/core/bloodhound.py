"""BloodHound CE-friendly export (JSON + zip).

Produces a structure close to SharpHound / BH CE file ingest:
  - nodes with kinds[] + properties (name, distinguishedname, domain, objectid)
  - edges with start/end value + kind (BH relationship names)
  - zip contains bloodhound.json, nodes.json, edges.json, meta.json
"""

from __future__ import annotations

import json
import zipfile
from datetime import UTC, datetime
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
    "GPO": "GPO",
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
    "ESC1": "ADCSESC1",
    "ESC1Candidate": "ADCSESC1",
    "ESC1Enrollable": "ADCSESC1",
    "ESC2": "ADCSESC2",
    "ESC3Agent": "ADCSESC3",
    "ESC3RequiresRA": "ADCSESC3",
    "ESC4": "ADCSESC4",
    "ESC7": "ADCSESC7",
    "ESC8WebEnrollment": "ADCSESC8",
    "Enroll": "Enroll",
    "AutoEnroll": "AutoEnroll",
    "ManageCA": "ManageCA",
    "ManageCertificates": "ManageCertificates",
    "GMSAPasswordReadable": "ReadGMSAPassword",
    "LAPSReadable": "ReadLAPSPassword",
    "UnconstrainedDelegation": "AllowedToDelegate",
    "AllowedToDelegate": "AllowedToDelegate",
    "HasSIDHistory": "HasSIDHistory",
    "HasKeyCredentialLink": "AddKeyCredentialLink",
    "WriteKeyCredentialLink": "AddKeyCredentialLink",
    "AllowedToAct": "AllowedToAct",
    "WriteRBCD": "AddAllowedToAct",
    "WriteGPO": "WriteGPO",
    "GPLink": "GPLink",
    "SpoolerOpen": "SpoolerOpen",
    "EfsrpcOpen": "EfsrpcOpen",
}


def _domain_from_id(node_id: str) -> str:
    parts = node_id.split("@")
    if len(parts) >= 3:
        return parts[-1]
    if len(parts) == 2 and parts[0] == "DOMAIN":
        return parts[1]
    return ""


def _object_id(node: Any) -> str:
    """Prefer SID-like property; else stable node id."""
    props = node.properties
    for key in ("objectid", "sid", "objectSid"):
        if props.get(key):
            return str(props[key])
    return node.id


def _node_properties(node: Any) -> dict[str, Any]:
    props = dict(node.properties)
    if "sam" in props and "name" not in props:
        props["name"] = props["sam"]
    if "dn" in props:
        props["distinguishedname"] = str(props["dn"]).upper()
    props["domain"] = (props.get("domain") or _domain_from_id(node.id) or "").upper()
    props["objectid"] = _object_id(node)
    # BH-friendly boolean flags
    for flag in (
        "admin_count",
        "dont_req_preauth",
        "unconstrained_delegation",
        "esc1_candidate",
        "esc2_candidate",
        "laps",
        "gmsa",
    ):
        if flag in props:
            props[flag] = bool(props[flag])
    return props


def export_bloodhound(graph: AttackGraph, domain: str | None = None) -> dict[str, Any]:
    nodes = []
    for n in graph.nodes.values():
        label = KIND_MAP.get(n.kind, n.kind)
        nodes.append(
            {
                "id": _object_id(n),
                "kinds": [label],
                "label": label,
                "properties": _node_properties(n),
            }
        )

    # id remap: graph internal id → objectid for edge endpoints when available
    id_map = {n.id: _object_id(n) for n in graph.nodes.values()}

    edges = []
    for e in graph.edges:
        rel = EDGE_MAP.get(e.kind, e.kind)
        edges.append(
            {
                "start": {"value": id_map.get(e.source, e.source)},
                "end": {"value": id_map.get(e.target, e.target)},
                "kind": rel,
                "properties": dict(e.properties),
            }
        )

    meta = {
        "source": "adaf-attack",
        "type": "bloodhound-ce",
        "version": 6,
        "generated_at": datetime.now(UTC).isoformat(),
        "domain": domain.upper() if domain else None,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "summary": graph.summary(),
        "collector": "adaf-attack",
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
    path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    return path


def save_bloodhound_zip(
    graph: AttackGraph,
    zip_path: Path,
    domain: str | None = None,
) -> Path:
    """Write a zip suitable for BloodHound CE file ingest."""
    doc = export_bloodhound(graph, domain=domain)
    zip_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bloodhound.json", json.dumps(doc, indent=2, default=str))
        zf.writestr("nodes.json", json.dumps(doc["nodes"], indent=2, default=str))
        zf.writestr("edges.json", json.dumps(doc["edges"], indent=2, default=str))
        zf.writestr("meta.json", json.dumps(doc["meta"], indent=2, default=str))

    return zip_path
