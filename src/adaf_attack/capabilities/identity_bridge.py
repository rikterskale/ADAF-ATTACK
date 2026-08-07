"""Hybrid identity signals and BloodHound graph round-trip helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ldap3 import SUBTREE

from adaf_attack.core.bloodhound import import_bloodhound, save_bloodhound, save_bloodhound_zip
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_util import ldap_connect
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


@register_capability(
    id="bloodhound-import",
    summary="Import BloodHound-compatible JSON, enrich locally, and re-export",
    category="export",
    tags=("bloodhound", "import", "round-trip"),
)
class BloodhoundImport:
    def run(
        self, target: Target, session: Session, graph: AttackGraph, **kwargs: Any
    ) -> dict[str, Any]:
        artifact = Path(str(kwargs.get("artifact") or ""))
        if not artifact.is_file():
            raise RuntimeError("bloodhound-import requires --artifact <BloodHound JSON>")
        result: dict[str, Any] = import_bloodhound(artifact, graph)
        graph.save(session.path("graph.json"))
        json_path = session.path("bloodhound-enriched.json")
        zip_path = session.path("bloodhound-enriched.zip")
        save_bloodhound(graph, json_path, target.domain)
        save_bloodhound_zip(graph, zip_path, target.domain)
        result.update(
            {"source": str(artifact), "json_path": str(json_path), "zip_path": str(zip_path)}
        )
        session.log("bloodhound-import.complete", **result)
        return result


@register_capability(
    id="hybrid-signals",
    summary="Detect on-premises hybrid identity and Entra pivot indicators",
    category="enumeration",
    tags=("hybrid", "entra", "azure-ad-connect", "pta", "phs"),
)
class HybridSignals:
    def run(
        self, target: Target, session: Session, graph: AttackGraph, **kwargs: Any
    ) -> dict[str, Any]:
        conn, base_dn, _cfg = ldap_connect(target)
        signals: list[dict[str, str]] = []
        conn.search(
            base_dn,
            "(|(objectClass=user)(objectClass=computer))",
            search_scope=SUBTREE,
            attributes=[
                "sAMAccountName",
                "description",
                "servicePrincipalName",
                "msDS-DeviceObjectVersion",
            ],
            size_limit=int(kwargs.get("max_objects") or 1000),
        )
        markers = {
            "azure ad connect": "Azure AD Connect",
            "adconnect": "Azure AD Connect",
            "pass-through authentication": "PTA",
            "seamless sso": "Seamless SSO",
        }
        for entry in conn.entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else "unknown"
            text = " ".join(
                [
                    str(entry.description) if entry.description else "",
                    *[str(x) for x in (entry.servicePrincipalName or [])],
                ]
            ).lower()
            for needle, label in markers.items():
                if needle in text:
                    signals.append({"principal": sam, "signal": label})
        conn.unbind()
        for signal in signals:
            source = f"IDENTITY@{signal['principal'].upper()}@{target.domain.upper()}"
            graph.add_node(source, "Base", sam=signal["principal"], hybrid_signal=signal["signal"])
            graph.add_edge(
                source,
                f"ENTRA@{target.domain.upper()}",
                "PossibleEntraPivot",
                signal=signal["signal"],
            )
        result: dict[str, Any] = {
            "domain": target.domain,
            "signals": signals,
            "count": len(signals),
            "note": "Signals indicate review paths only; no Entra action is performed.",
        }
        session.path("hybrid-signals.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        graph.save(session.path("graph.json"))
        session.log("hybrid-signals.complete", count=len(signals))
        return result
