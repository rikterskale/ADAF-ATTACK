"""Offline correlation workflows over existing ADAF session artifacts.

These helpers intentionally consume saved evidence and never contact a domain
controller or replay an attack. They are suitable for review, planning, and
purple-team handoff after an authorized assessment.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

SENSITIVE_WORDS = ("password", "hash", "ticket", "ccache", "pfx", "secret", "key")

# The baseline is deliberately read-only.  It is shared by the dedicated
# ``ad-recon`` CLI surface and the engagement-plan template so operators get
# one consistent collection story and one session graph.
AD_RECON_CAPABILITIES = (
    "ldap-enum",
    "trusts-enum",
    "acl-enum",
    "adcs-enum",
    "gpo-abuse",
    "rodc-delegation",
    "gmsa-laps-enum",
    "ad-cve-scan",
)

AD_RECON_PHASES = (
    {
        "name": "identity-and-topology",
        "capabilities": ["ldap-enum", "trusts-enum"],
    },
    {
        "name": "control-paths",
        "capabilities": ["acl-enum", "adcs-enum", "gpo-abuse", "rodc-delegation"],
    },
    {
        "name": "credential-and-hardening-exposure",
        "capabilities": ["gmsa-laps-enum", "ad-cve-scan"],
    },
)


def ad_recon_plan_data() -> dict[str, Any]:
    """Return an editable, scoped starter plan for credentialed AD recon."""
    return {
        "engagement_id": "ENG-YYYY-AD-RECON",
        "target": {"domain": "corp.example", "dc_ip": "10.0.0.10"},
        "allowed_targets": ["10.0.0.10"],
        "opsec_profile": "balanced",
        "allowed_capabilities": list(AD_RECON_CAPABILITIES),
        "phases": [dict(phase) for phase in AD_RECON_PHASES],
    }

PROFILES: dict[str, dict[str, Any]] = {
    "ad-recon": {
        "description": (
            "Credentialed, read-only Active Directory reconnaissance: identity, trust, "
            "control-path, credential-exposure, and hardening evidence."
        ),
        "steps": list(AD_RECON_CAPABILITIES),
        "network_effect": "LDAP/SMB posture queries against the in-scope domain controller.",
        "execution": "adaf-attack ad-recon init --output ad-recon.yaml, then validate and run it.",
    },
    "discovery": {
        "description": "Inventory LDAP, trust, and AD CS evidence.",
        "steps": ["ldap-enum", "trusts-enum", "adcs-enum"],
    },
    "path-analysis": {
        "description": "Correlate saved graph paths and exposure evidence.",
        "steps": ["credential-exposure", "bloodhound-reconcile", "campaign-compose"],
    },
    "delegation": {
        "description": "Review delegation and RBCD evidence.",
        "steps": ["delegation-validation", "trust-correlation"],
    },
    "purple-team": {
        "description": "Prepare a detection-oriented evidence handoff.",
        "steps": ["coercion-fixtures", "purple-handoff"],
    },
}


def _read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def session_evidence(session: Path) -> dict[str, Any]:
    """Return non-secret inventory and graph evidence for one session directory."""
    artifacts = sorted(path.name for path in session.glob("*.json") if path.name != "session.json")
    graph = _read_json(session / "graph.json") or {}
    edges = graph.get("edges", []) if isinstance(graph, dict) else []
    edge_kinds = Counter(edge.get("kind", "unknown") for edge in edges if isinstance(edge, dict))
    sensitive = [
        path.name
        for path in session.iterdir()
        if path.is_file() and any(word in path.name.lower() for word in SENSITIVE_WORDS)
    ]
    return {
        "session": str(session),
        "artifacts": artifacts,
        "edge_kinds": dict(sorted(edge_kinds.items())),
        "sensitive_artifacts": sorted(sensitive),
    }


def credential_exposure(sessions: list[Path]) -> dict[str, Any]:
    evidence = [session_evidence(path) for path in sessions]
    exposures = [
        {
            "session": item["session"],
            "artifact": artifact,
            "priority": "high",
            "secret_value": "redacted",
        }
        for item in evidence
        for artifact in item["sensitive_artifacts"]
    ]
    return {
        "sessions": evidence,
        "exposures": exposures,
        "count": len(exposures),
        "next_step": "Review the referenced session artifact under the engagement's evidence-handling procedure.",
    }


def bloodhound_reconcile(session: Path, bloodhound: Path) -> dict[str, Any]:
    local = _read_json(session / "graph.json") or {}
    external = _read_json(bloodhound) or {}
    local_nodes = {item.get("id") for item in local.get("nodes", []) if isinstance(item, dict)}
    external_nodes = {
        item.get("id") for item in external.get("nodes", []) if isinstance(item, dict)
    }
    return {
        "session": str(session),
        "bloodhound": str(bloodhound),
        "local_node_count": len(local_nodes),
        "bloodhound_node_count": len(external_nodes),
        "only_local": sorted(local_nodes - external_nodes),
        "only_bloodhound": sorted(external_nodes - local_nodes),
        "next_step": "Investigate gaps as collection-scope or normalization differences before acting on them.",
    }


def correlate_trusts(sessions: list[Path]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for session in sessions:
        trusts = _read_json(session / "trusts-enum.json") or {}
        graph = session_evidence(session)
        records.append(
            {
                "session": str(session),
                "trusts": trusts.get("trusts", []) if isinstance(trusts, dict) else [],
                "trusted_by_edges": graph["edge_kinds"].get("TrustedBy", 0),
            }
        )
    return {
        "records": records,
        "next_step": "Confirm each cross-forest path against authorized identity and trust documentation.",
    }


def validate_surface(session: Path, kind: str) -> dict[str, Any]:
    evidence = session_evidence(session)
    matchers = {
        "delegation": ("delegat", "AllowedToAct", "WriteRBCD"),
        "adcs": ("ESC", "Enroll", "ManageCA", "ManageCertificates"),
        "gpo": ("WriteGPO", "GPLink", "WriteSYSVOL"),
        "coercion": ("SpoolerOpen", "EfsrpcOpen"),
    }[kind]
    findings = {
        edge: count
        for edge, count in evidence["edge_kinds"].items()
        if any(token.lower() in edge.lower() for token in matchers)
    }
    artifacts = [
        name
        for name in evidence["artifacts"]
        if kind in name or (kind == "adcs" and "cert" in name)
    ]
    return {
        "kind": kind,
        "session": str(session),
        "findings": findings,
        "artifacts": artifacts,
        "validated": bool(findings or artifacts),
        "next_step": "Treat this as evidence validation only; obtain authorization before any state-changing confirmation.",
    }


def compose_campaign(sessions: list[Path]) -> dict[str, Any]:
    evidence = [session_evidence(path) for path in sessions]
    phases = [
        {
            "session": item["session"],
            "artifacts": item["artifacts"],
            "risk_signals": sorted(item["edge_kinds"].keys()),
        }
        for item in evidence
    ]
    return {
        "phases": phases,
        "next_step": "Review the proposed sequence with the engagement owner; this composer does not execute actions.",
    }


def purple_handoff(session: Path) -> dict[str, Any]:
    evidence = session_evidence(session)
    mapping = {
        "DCSync": "Directory replication access",
        "ESC1": "Certificate enrollment abuse",
        "WriteGPO": "Group Policy modification",
        "SpoolerOpen": "Coercion exposure",
    }
    detections = [
        {"signal": edge, "detection_focus": description}
        for edge, description in mapping.items()
        if edge in evidence["edge_kinds"]
    ]
    return {
        "session": str(session),
        "detections": detections,
        "next_step": "Share these evidence-backed detection hypotheses with defenders; do not replay production activity.",
    }


def validate_fixtures(fixtures: Path) -> dict[str, Any]:
    documents = []
    for path in sorted(fixtures.glob("*.json")):
        data = _read_json(path)
        documents.append({"fixture": path.name, "valid_json": data is not None})
    return {
        "fixtures": documents,
        "valid": bool(documents) and all(item["valid_json"] for item in documents),
        "next_step": "Use only authorized, isolated fixtures for coercion detection validation.",
    }
