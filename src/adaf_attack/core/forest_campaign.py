"""Forest-aware, evidence-only campaign planning across completed sessions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adaf_attack.core.graph import AttackGraph


def compose_forest_campaign(sessions: list[Path]) -> dict[str, Any]:
    merged = AttackGraph()
    domains: list[str] = []
    vault_refs: list[dict[str, Any]] = []
    for session in sessions:
        graph_path = session / "graph.json"
        if graph_path.is_file():
            graph = AttackGraph.from_file(graph_path)
            merged.load_dict(graph.to_dict())
        metadata = json.loads((session / "session.json").read_text(encoding="utf-8")) if (session / "session.json").is_file() else {}
        if metadata.get("domain"):
            domains.append(str(metadata["domain"]))
        index = session / "vault" / "index.json"
        if index.is_file():
            data = json.loads(index.read_text(encoding="utf-8"))
            vault_refs.extend({"session": str(session), "name": name, "kind": item.get("kind"), "secret": bool(item.get("secret"))} for name, item in data.get("items", {}).items())
    transitions = [edge for edge in merged.to_dict()["edges"] if edge["kind"] in {"TrustedBy", "SameForestTrust", "ExternalTrust"}]
    return {"domains": sorted(set(domains)), "graph": merged.summary(), "trust_transitions": transitions, "vault_references": vault_refs, "stop_conditions": ["Stop before any state-changing capability without an approval token.", "Stop on an untrusted or out-of-scope domain transition."], "next_step": "Review transitions and run only engagement-authorized phases in the next domain."}
