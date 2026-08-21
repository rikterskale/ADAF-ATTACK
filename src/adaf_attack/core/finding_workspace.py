"""Unified, read-only finding workspace assembled from session evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adaf_attack.core.rollback import cleanup_dashboard


def build_finding_workspace(session: Path, finding: dict[str, Any]) -> dict[str, Any]:
    """Return one actionable finding record for operators and reporting."""
    session = Path(session)
    evidence = finding.get("evidence") or []
    if isinstance(evidence, dict):
        evidence = [evidence]
    if not isinstance(evidence, list):
        evidence = []
    evidence_records = []
    for item in evidence:
        if isinstance(item, str):
            artifact = item
            pointer = "/"
            digest = None
        elif isinstance(item, dict):
            artifact = str(item.get("artifact") or item.get("path") or "")
            pointer = str(item.get("pointer") or "/")
            digest = item.get("sha256")
        else:
            continue
        path = session / artifact
        evidence_records.append(
            {
                "artifact": artifact,
                "pointer": pointer,
                "sha256": digest,
                "present": path.is_file(),
                "freshness": "current" if path.is_file() else "missing",
            }
        )
    present = sum(bool(item["present"]) for item in evidence_records)
    status = str(finding.get("status") or "open").lower()
    severity = str(finding.get("severity") or "unknown").lower()
    confidence = str(finding.get("confidence") or "unknown").lower()
    finding_id = finding.get("id") or finding.get("finding_id") or finding.get("title")
    source = finding.get("source_capability") or finding.get("source") or "operator observation"
    validation = [
        {"id": "review-evidence", "action": f"Review evidence for {finding_id}"},
        {
            "id": "record-detection",
            "action": "Record expected telemetry and defensive detection status",
        },
    ]
    if source and source != "operator observation":
        validation.insert(
            0, {"id": "repeat-source", "action": f"Review or rerun the source capability: {source}"}
        )
    if status in {"closed", "mitigated", "remediated"}:
        next_actions = [
            {"id": "verify-closure", "action": "Verify remediation evidence and detection status"}
        ]
    elif present < len(evidence_records) or not evidence_records:
        next_actions = [
            {"id": "capture-evidence", "action": "Capture or restore the missing evidence artifact"}
        ] + validation
    else:
        next_actions = validation + [
            {
                "id": "prepare-remediation",
                "action": "Review remediation guidance and assign an owner",
            }
        ]
    technique_values = finding.get("attack_techniques") or finding.get("techniques") or []
    if isinstance(technique_values, str):
        technique_values = [technique_values]
    return {
        "id": finding_id,
        "title": finding.get("title") or finding.get("name") or "untitled finding",
        "status": status,
        "severity": severity,
        "confidence": confidence,
        "priority": {"critical": 100, "high": 80, "medium": 55, "low": 30}.get(severity, 15)
        + {"confirmed": 20, "high": 15, "medium": 8}.get(confidence, 0),
        "plain_language": finding.get("impact")
        or "This finding represents an observed security condition requiring review.",
        "impact": finding.get("impact") or "Impact requires operator validation.",
        "remediation": finding.get("remediation")
        or "Review the affected control and verify remediation.",
        "detection_guidance": {
            "techniques": list(technique_values),
            "expected_telemetry": [
                "Directory service audit events",
                "Endpoint or SIEM correlation where applicable",
            ],
            "status": "not-recorded",
        },
        "evidence": evidence_records,
        "evidence_quality": {
            "captured": present,
            "expected": len(evidence_records),
            "status": "complete"
            if evidence_records and present == len(evidence_records)
            else "incomplete",
        },
        "affected_assets": finding.get("affected_assets") or finding.get("assets") or [],
        "source": source,
        "validation_options": validation,
        "cleanup": cleanup_dashboard(session),
        "next_actions": next_actions,
    }


def load_finding_workspace(session: Path, finding_id: str) -> dict[str, Any]:
    """Load a finding by ID/title and build its workspace, raising clear errors."""
    try:
        payload = json.loads((Path(session) / "findings.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read findings.json: {exc}") from exc
    values = payload.get("findings") if isinstance(payload, dict) else payload
    if not isinstance(values, list):
        values = []
    for item in values:
        if not isinstance(item, dict):
            continue
        aliases = {
            str(item.get("id") or ""),
            str(item.get("finding_id") or ""),
            str(item.get("title") or ""),
        }
        if finding_id in aliases:
            return build_finding_workspace(Path(session), item)
    raise ValueError(f"Finding not found: {finding_id}")
