"""Operator tool services built on saved evidence and explicit scope documents."""

from __future__ import annotations

import json
import shutil
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from adaf_attack.core.graph import AttackGraph


def graph_explorer(graph_path: Path, *, start: str | None = None, limit: int = 25) -> dict[str, Any]:
    """Return a compact explorer payload for graph UIs and API clients."""
    graph = AttackGraph.from_file(graph_path)
    summary = graph.summary()
    ranked = graph.rank_from_principals([start] if start else None, max_depth=6, limit=limit)
    relations = Counter(str(getattr(edge, "kind", "unknown")) for edge in graph.edges)
    return {
        "graph": str(graph_path),
        "summary": summary,
        "relation_counts": dict(sorted(relations.items())),
        "start": start,
        "paths": ranked,
        "path_count": len(ranked),
        "offline": True,
    }


def import_evidence(session: Path, source: Path, *, overwrite: bool = False) -> dict[str, Any]:
    """Copy a validated JSON evidence artifact into a session import area."""
    if not session.is_dir():
        raise FileNotFoundError(f"Session directory not found: {session}")
    if not source.is_file():
        raise FileNotFoundError(f"Evidence file not found: {source}")
    document = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("Evidence must contain a JSON object at the top level")
    destination = session / "imports" / source.name
    if destination.exists() and not overwrite:
        raise FileExistsError(f"Evidence import already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    manifest_path = session / "imports" / "manifest.jsonl"
    record = {
        "imported_at": datetime.now(UTC).isoformat(),
        "source_name": source.name,
        "destination": str(destination),
        "keys": sorted(str(key) for key in document),
    }
    with manifest_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    return {"ok": True, "source": str(source), "destination": str(destination), "record": record}


def verify_finding(session: Path, finding_id: str, *, evidence: list[str] | None = None) -> dict[str, Any]:
    """Mark a finding as remediated only with an explicit verification record."""
    path = session / "findings.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    findings = document.get("findings") if isinstance(document, dict) else None
    if not isinstance(findings, list):
        raise ValueError("findings.json does not contain a findings list")
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = str(finding.get("id") or finding.get("finding_id") or finding.get("title") or "")
        if key != finding_id:
            continue
        verification = {
            "verified_at": datetime.now(UTC).isoformat(),
            "evidence": list(evidence or []),
            "method": "operator-supplied verification evidence",
        }
        finding["status"] = "remediated"
        finding["verification"] = verification
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        return {"ok": True, "finding": finding, "verification": verification}
    raise KeyError(f"Finding not found: {finding_id}")


def scope_summary(path: Path) -> dict[str, Any]:
    """Inspect a YAML engagement scope without executing it."""
    import yaml

    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("Scope document must contain a mapping")
    target = raw.get("target") if isinstance(raw.get("target"), dict) else {}
    allowed = raw.get("allowed_targets") or []
    capabilities = raw.get("allowed_capabilities") or []
    phases = raw.get("phases") or []
    return {
        "path": str(path),
        "engagement_id": raw.get("engagement_id"),
        "target": target,
        "allowed_targets": allowed if isinstance(allowed, list) else [allowed],
        "allowed_capabilities": capabilities if isinstance(capabilities, list) else [capabilities],
        "phase_count": len(phases) if isinstance(phases, list) else 0,
        "opsec_profile": raw.get("opsec_profile", "balanced"),
        "execution": "inspection-only",
    }


def detection_export(session: Path) -> dict[str, Any]:
    """Generate detection hypotheses from evidence-backed graph relations."""
    graph = json.loads((session / "graph.json").read_text(encoding="utf-8")) if (session / "graph.json").is_file() else {}
    edges = graph.get("edges", []) if isinstance(graph, dict) else []
    mapping = {
        "DCSync": ("directory-replication-access", [4662]),
        "WriteGPO": ("group-policy-modification", [5136, 5141]),
        "ESC1": ("certificate-enrollment-abuse", [4886, 4887]),
        "SpoolerOpen": ("coercion-attempt", [5145]),
        "AllowedToAct": ("resource-based-constrained-delegation", [5136]),
    }
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for edge in edges if isinstance(edges, list) else []:
        if not isinstance(edge, dict):
            continue
        kind = str(edge.get("kind", ""))
        if kind in mapping and kind not in seen:
            title, event_ids = mapping[kind]
            rules.append({
                "id": f"ADAF-{kind.upper()}",
                "title": title,
                "source_relation": kind,
                "logsource": {"product": "windows", "service": "security"},
                "event_ids": event_ids,
                "status": "hypothesis-review-required",
            })
            seen.add(kind)
    return {"ok": True, "session": str(session), "rules": rules, "count": len(rules), "offline": True}


def lab_manifest_summary(path: Path) -> dict[str, Any]:
    """Validate and summarize a disposable lab manifest without network access."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("Lab manifest must contain a JSON object")
    domain = str(document.get("domain", "")).lower()
    reserved = domain.endswith((".lab", ".test", ".example"))
    return {
        "path": str(path),
        "domain": domain,
        "reserved_domain": reserved,
        "snapshot": document.get("snapshot"),
        "fixtures": document.get("fixtures", []),
        "allowlist_count": len(document.get("allowlist", [])) if isinstance(document.get("allowlist"), list) else 0,
        "network_contact": False,
        "ready_for_review": bool(domain and reserved and document.get("snapshot")),
    }
