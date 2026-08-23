"""Forest-aware, evidence-only campaign planning across completed sessions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.vault import SessionVault, VaultError


class CampaignError(ValueError):
    """Raised when a campaign manifest is malformed or cannot be executed."""


def load_campaign_manifest(path: Path) -> tuple[str, list[Path]]:
    """Load an ordered set of engagement plans from a campaign YAML file."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise CampaignError(f"Cannot load campaign YAML: {exc}") from exc
    campaign_id = str(raw.get("campaign_id", "")).strip()
    entries = raw.get("engagements")
    if not campaign_id or not isinstance(entries, list) or not entries:
        raise CampaignError("campaign_id and a non-empty engagements list are required")
    plans: list[Path] = []
    for entry in entries:
        value = entry.get("plan") if isinstance(entry, dict) else entry
        if not value:
            raise CampaignError("Each engagement must specify a plan path")
        plan = (path.parent / str(value)).resolve()
        if not plan.is_file():
            raise CampaignError(f"Engagement plan not found: {plan}")
        plans.append(plan)
    return campaign_id, plans


def _campaign_entries(path: Path) -> tuple[str, list[dict[str, Any]]]:
    """Load manifest entries, retaining explicit credential-handoff requests."""
    campaign_id, plans = load_campaign_manifest(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries: list[dict[str, Any]] = []
    for source, plan in zip(raw["engagements"], plans, strict=True):
        entry = dict(source) if isinstance(source, dict) else {}
        entry["_plan"] = plan
        entries.append(entry)
    return campaign_id, entries


def _handoff_ccache(
    entry: dict[str, Any], manifest: Path
) -> tuple[str | None, dict[str, Any] | None]:
    """Resolve an opt-in CCache reference without exposing its contents."""
    handoff = entry.get("credential_handoff")
    if handoff is None:
        return None, None
    if not isinstance(handoff, dict) or handoff.get("allow") is not True:
        raise CampaignError("credential_handoff requires an explicit allow: true")
    source = handoff.get("from_session")
    item = str(handoff.get("item", "tgt"))
    if not source or item != "tgt":
        raise CampaignError("credential_handoff supports only the explicit vault item 'tgt'")
    session_path = (manifest.parent / str(source)).resolve()
    try:
        value = SessionVault(session_path).get(item)
    except VaultError as exc:
        raise CampaignError(f"Unable to load credential handoff: {exc}") from exc
    ccache = Path(str(value.get("path") if isinstance(value, dict) else ""))
    if not ccache.is_file():
        raise CampaignError("Credential handoff TGT does not reference an available ccache")
    return str(ccache), {"from_session": str(session_path), "item": item, "kind": "ccache"}


def run_campaign(
    manifest: Path,
    *,
    workspace: Path,
    username: str | None = None,
    password: str | None = None,
    approval_tokens: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Execute ordered, independently authorized engagement plans.

    Each plan retains its target and capability scope.  A destructive phase only
    receives the token mapped to that engagement ID, so credentials and approval
    do not silently cross a domain boundary.
    """
    from adaf_attack.core.engagement import load_plan, run_engagement

    campaign_id, entries = _campaign_entries(manifest)
    approval_tokens = approval_tokens or {}
    completed: list[dict[str, Any]] = []
    session_paths: list[Path] = []
    for entry in entries:
        plan_path = entry["_plan"]
        plan = load_plan(plan_path)
        try:
            ccache, handoff = _handoff_ccache(entry, manifest)
            result = run_engagement(
                plan,
                workspace=workspace / campaign_id,
                username=username,
                password=password,
                approval_token=approval_tokens.get(plan.engagement_id),
                ccache=ccache,
            )
        except Exception as exc:
            return {
                "campaign_id": campaign_id,
                "completed": completed,
                "stopped": True,
                "failed_engagement": plan.engagement_id,
                "error": str(exc),
                "next_step": "Resolve the failed scoped engagement before resuming the campaign.",
            }
        completed.append(
            {
                "engagement_id": plan.engagement_id,
                "domain": plan.domain,
                "session_path": result["session_path"],
                "credential_handoff": handoff,
            }
        )
        session_paths.append(Path(result["session_path"]))

    forest = compose_forest_campaign(session_paths)
    result = {
        "campaign_id": campaign_id,
        "completed": completed,
        "stopped": False,
        "forest": forest,
        "next_step": "Review the merged evidence and cleanup status for every completed engagement.",
    }
    output = workspace / campaign_id / "campaign.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def compose_forest_campaign(sessions: list[Path]) -> dict[str, Any]:
    merged = AttackGraph()
    domains: list[str] = []
    vault_refs: list[dict[str, Any]] = []
    for session in sessions:
        graph_path = session / "graph.json"
        if graph_path.is_file():
            graph = AttackGraph.from_file(graph_path)
            merged.load_dict(graph.to_dict())
        metadata = (
            json.loads((session / "session.json").read_text(encoding="utf-8"))
            if (session / "session.json").is_file()
            else {}
        )
        if metadata.get("domain"):
            domains.append(str(metadata["domain"]))
        index = session / "vault" / "index.json"
        if index.is_file():
            data = json.loads(index.read_text(encoding="utf-8"))
            vault_refs.extend(
                {
                    "session": str(session),
                    "name": name,
                    "kind": item.get("kind"),
                    "secret": bool(item.get("secret")),
                }
                for name, item in data.get("items", {}).items()
            )
    transitions = [
        edge
        for edge in merged.to_dict()["edges"]
        if edge["kind"] in {"TrustedBy", "SameForestTrust", "ExternalTrust"}
    ]
    return {
        "domains": sorted(set(domains)),
        "graph": merged.summary(),
        "trust_transitions": transitions,
        "vault_references": vault_refs,
        "stop_conditions": [
            "Stop before any state-changing capability without an approval token.",
            "Stop on an untrusted or out-of-scope domain transition.",
        ],
        "next_step": "Review transitions and run only engagement-authorized phases in the next domain.",
    }
