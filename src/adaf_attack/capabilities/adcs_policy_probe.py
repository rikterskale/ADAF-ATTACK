"""Evaluate authorized AD CS policy evidence for ESC10–ESC13."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


@register_capability(
    id="adcs-policy-probe",
    summary="Evaluate CA/DC policy evidence for ESC10–ESC13",
    category="enumeration",
    tags=("adcs", "esc10", "esc11", "esc13"),
)
class AdcsPolicyProbe:
    def run(self, target: Target, session: Session, graph: AttackGraph, **kwargs: Any) -> dict[str, Any]:
        source = Path(str(kwargs.get("artifact") or ""))
        if not source.is_file():
            raise RuntimeError("adcs-policy-probe requires --artifact <authorized policy JSON>")
        data = json.loads(source.read_text(encoding="utf-8"))
        result: dict[str, list[str]] = {
            "esc10_candidates": ["dc-policy"] if data.get("weak_certificate_mapping") else [],
            "esc11_candidates": ["ca-rpc"] if data.get("rpc_encryption_not_enforced") else [],
            "esc13_candidates": [str(x) for x in data.get("issuance_policy_group_links") or []],
        }
        for key, relation in (("esc10_candidates", "ESC10"), ("esc11_candidates", "ESC11"), ("esc13_candidates", "ESC13")):
            for evidence in result[key]:
                domain = f"DOMAIN@{target.domain.upper()}"
                graph.add_edge(domain, domain, relation, evidence=evidence)
        session.path("adcs-policy-probe.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        session.log("adcs-policy-probe.complete", **{key: len(value) for key, value in result.items()})
        return result
