"""Evaluate authorized AD CS policy evidence for ESC10-ESC15."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adaf_attack.core.adcs_analyze import classify_modern_esc
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


@register_capability(
    id="adcs-policy-probe",
    summary="Evaluate CA/DC policy evidence for ESC10-ESC15",
    category="enumeration",
    tags=("adcs", "esc10", "esc11", "esc13", "esc14", "esc15", "policy"),
)
class AdcsPolicyProbe:
    def run(
        self, target: Target, session: Session, graph: AttackGraph, **kwargs: Any
    ) -> dict[str, Any]:
        source = Path(str(kwargs.get("artifact") or ""))
        if not source.is_file():
            raise RuntimeError("adcs-policy-probe requires --artifact <authorized policy JSON>")
        data = json.loads(source.read_text(encoding="utf-8"))

        classified = classify_modern_esc(policy=data)
        result: dict[str, Any] = {
            "esc10_candidates": ["dc-policy"] if data.get("weak_certificate_mapping") else [],
            "esc11_candidates": ["ca-rpc"] if data.get("rpc_encryption_not_enforced") else [],
            "esc13_candidates": [str(x) for x in data.get("issuance_policy_group_links") or []],
        }
        if data.get("shell_access_via_certificate"):
            result["esc14_candidates"] = ["shell-path"]
        if data.get("privileged_enrollment_agent"):
            result["esc15_candidates"] = ["enrollment-agent"]

        domain = f"DOMAIN@{target.domain.upper()}"
        for esc, meta in classified.get("candidates", {}).items():
            if esc in {"ESC10", "ESC11", "ESC13", "ESC14", "ESC15"}:
                graph.add_edge(
                    domain,
                    domain,
                    esc,
                    evidence=meta.get("reason"),
                    confidence=meta.get("confidence"),
                )

        session.path("adcs-policy-probe.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        session.log(
            "adcs-policy-probe.complete",
            **{
                key: len(value)
                for key, value in result.items()
                if key.endswith("_candidates") and isinstance(value, list)
            },
        )
        return result
