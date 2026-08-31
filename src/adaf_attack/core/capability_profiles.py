"""Curated, deterministic groups of capabilities for operator workflows."""

from __future__ import annotations

from typing import Any

from adaf_attack.core.registry import (
    Capability,
    capability_registry,
    load_builtin_capabilities,
)
from adaf_attack.core.workflows import AD_RECON_CAPABILITIES

PROFILE_DEFINITIONS: dict[str, dict[str, Any]] = {
    "recon": {
        "description": "Read-only Active Directory reconnaissance and exposure collection.",
        "capabilities": tuple(AD_RECON_CAPABILITIES),
        "read_only": True,
    },
    "adcs": {
        "description": "AD CS discovery, validation, and approved exploitation capabilities.",
        "tags_any": ("adcs",),
        "read_only": False,
    },
    "lateral-movement": {
        "description": "Capabilities that establish or exercise lateral movement paths.",
        "category": "lateral-movement",
        "read_only": False,
    },
    "persistence": {
        "description": "Capabilities that establish persistence in an authorized domain.",
        "category": "persistence",
        "read_only": False,
    },
    "unauthenticated": {
        "description": "Credential-free network and directory posture collection.",
        "capabilities": (
            "anonymous-ldap-probe",
            "passive-discovery",
            "external-exposure",
            "timeroast",
            "asrep-roast",
            "asreq-userhunt",
            "pre2k-spray",
        ),
        "read_only": True,
        "credential_free": True,
    },
    "offline-analysis": {
        "description": "Saved-evidence analysis, correlation, and reporting; no network contact.",
        "capabilities": (
            "attack-paths",
            "bloodhound-export",
            "bloodhound-import",
            "campaign-analysis",
            "next-actions",
            "report",
            "rollback",
        ),
        "read_only": True,
        "offline": True,
        "steps": (
            "credential-exposure",
            "bloodhound-reconcile",
            "rank-paths",
            "trust-correlation",
            "delegation-validation",
            "adcs-validation",
            "engagement report",
            "purple-handoff",
        ),
    },
}


def profile_names() -> list[str]:
    return sorted(PROFILE_DEFINITIONS)


def resolve_profile(
    name: str,
    *,
    include_mutating: bool = False,
    include_noisy: bool = False,
    include_username_dependent: bool = False,
) -> dict[str, Any]:
    """Resolve a profile to registered capabilities and explicit skips."""
    load_builtin_capabilities()
    definition = PROFILE_DEFINITIONS.get(name)
    if definition is None:
        raise KeyError(name)
    if "capabilities" in definition:
        candidates = [capability_registry.get(item) for item in definition["capabilities"]]
        caps = [cap for cap in candidates if cap is not None]
    else:
        category = definition.get("category")
        tags_any = set(definition.get("tags_any", ()))
        caps = [
            cap
            for cap in capability_registry.list()
            if (category and cap.category == category) or tags_any.intersection(cap.tags)
        ]
    selected: list[Capability] = []
    skipped: list[dict[str, str]] = []
    for cap in caps:
        if cap.runner is None:
            skipped.append({"id": cap.id, "reason": "runner unavailable"})
        elif cap.requires_username_list and not include_username_dependent:
            skipped.append({"id": cap.id, "reason": "requires --include-username-dependent"})
        elif cap.active_authentication and not include_noisy:
            skipped.append({"id": cap.id, "reason": "requires --include-noisy"})
        elif not include_mutating and cap.requires_force:
            skipped.append({"id": cap.id, "reason": "requires --include-mutating"})
        else:
            selected.append(cap)
    return {
        "name": name,
        "description": definition["description"],
        "read_only": not include_mutating and all(not cap.requires_force for cap in selected),
        "include_mutating": include_mutating,
        "include_noisy": include_noisy,
        "include_username_dependent": include_username_dependent,
        "mode": "offline" if definition.get("offline") else "live",
        "workflow_steps": list(definition.get("steps", ())),
        "capabilities": selected,
        "skipped": skipped,
    }


def profile_plan(
    name: str,
    *,
    include_mutating: bool = False,
    include_noisy: bool = False,
    include_username_dependent: bool = False,
) -> dict[str, Any]:
    resolved = resolve_profile(
        name,
        include_mutating=include_mutating,
        include_noisy=include_noisy,
        include_username_dependent=include_username_dependent,
    )
    capabilities = resolved["capabilities"]
    return {
        "name": name,
        "description": resolved["description"],
        "read_only": resolved["read_only"],
        "include_mutating": include_mutating,
        "include_noisy": include_noisy,
        "include_username_dependent": include_username_dependent,
        "mode": resolved["mode"],
        "workflow_steps": resolved["workflow_steps"],
        "capabilities": [
            {
                "id": cap.id,
                "summary": cap.summary,
                "category": cap.category,
                "environment": cap.environment,
                "risk": cap.safety.risk.value if cap.safety else "observe",
                "requires_force": cap.requires_force,
                "tools": list(cap.tools),
                "auth_modes": list(cap.auth_modes),
                "requires_username_list": cap.requires_username_list,
                "active_authentication": cap.active_authentication,
                "noise_level": cap.noise_level or "unspecified",
                "data_sensitivity": cap.data_sensitivity,
            }
            for cap in capabilities
        ],
        "skipped": resolved["skipped"],
        "count": len(capabilities),
        "next_step": (
            "Run the listed workflow steps against saved evidence."
            if resolved["mode"] == "offline"
            else f"Review this profile, then run `adaf-attack capability-profile run {name} --yes`."
        ),
    }
