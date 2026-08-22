"""Read-only investigation workspace assembled from pinned local evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adaf_attack.core.asset_workspace import _load_findings
from adaf_attack.core.graph import AttackGraph


def _load_workspace(session: Path) -> dict[str, Any]:
    try:
        value = json.loads((session / "investigation.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _pin_values(workspace: dict[str, Any], key: str) -> list[str]:
    values = workspace.get(key, [])
    if not isinstance(values, list):
        return []
    return [
        str(value.get("id") or value.get("name") or value.get("value"))
        if isinstance(value, dict)
        else str(value)
        for value in values
        if value
    ]


def _load_events(session: Path) -> list[dict[str, Any]]:
    path = session / "events.jsonl"
    if not path.is_file():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            events.append(value)
    return events


def _matches(value: Any, pins: list[str]) -> bool:
    text = str(value).casefold()
    return any(pin.casefold() in text for pin in pins)


def build_investigation_workspace(session: Path) -> dict[str, Any]:
    """Return pinned investigation context without contacting any target."""
    session = Path(session)
    workspace = _load_workspace(session)
    finding_pins = _pin_values(workspace, "findings")
    identity_pins = _pin_values(workspace, "identities")
    asset_pins = _pin_values(workspace, "assets")
    credential_pins = _pin_values(workspace, "credentials")
    evidence_pins = _pin_values(workspace, "evidence")
    graph: AttackGraph | None = None
    graph_path = session / "graph.json"
    if graph_path.is_file():
        try:
            graph = AttackGraph.from_file(graph_path)
        except (OSError, KeyError, TypeError, ValueError):
            graph = None
    findings = [
        finding
        for finding in _load_findings(session)
        if _matches(finding.get("id") or finding.get("title"), finding_pins)
    ]
    nodes = []
    if graph:
        nodes = [
            {"id": node.id, "kind": node.kind, "properties": node.properties}
            for node in graph.nodes.values()
            if _matches(node.id, identity_pins + asset_pins)
        ]
    events = [
        event
        for event in _load_events(session)
        if _matches(event, identity_pins + asset_pins + credential_pins)
    ]
    artifacts = [{"path": value, "present": (session / value).is_file()} for value in evidence_pins]
    pinned = {
        "findings": finding_pins,
        "identities": identity_pins,
        "assets": asset_pins,
        "credentials": credential_pins,
        "evidence": evidence_pins,
    }
    total_pins = sum(len(values) for values in pinned.values())
    return {
        "ok": True,
        "session": str(session),
        "title": workspace.get("title") or "Investigation workspace",
        "notes": workspace.get("notes") or "",
        "pinned": pinned,
        "findings": findings,
        "nodes": nodes,
        "events": events,
        "artifacts": artifacts,
        "health": {
            "workspace": "configured" if total_pins else "empty",
            "graph": "present" if graph else "missing or unreadable",
            "events": "present" if events else "empty",
            "evidence": "present" if artifacts else "empty",
        },
        "summary": {
            "pins": total_pins,
            "findings": len(findings),
            "nodes": len(nodes),
            "events": len(events),
            "artifacts": len(artifacts),
        },
    }
