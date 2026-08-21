"""Extended UX helpers for operator enhancements (prerequisites, dashboard, export)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from adaf_attack.core.registry import Capability, capability_registry


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return cast(dict[str, Any], value) if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


_PRODUCERS: dict[str, list[str]] = {
    "ldap-enum": ["acl-enum", "adcs-enum", "attack-paths", "bloodhound-export", "gmsa-laps-enum"],
    "trusts-enum": ["forest-campaign", "trust-correlation", "attack-paths"],
    "adcs-enum": ["cert-request", "esc-chain", "adcs-validation", "template-mod"],
    "acl-enum": ["acl-write", "rbcd", "shadow-creds", "gpo-abuse", "attack-paths"],
    "gmsa-laps-enum": ["laps-read"],
    "kerberoast": ["ticket-lifecycle", "impacket-exec"],
    "asrep-roast": ["ticket-lifecycle"],
    "shadow-creds": ["pkinit-auth", "unpac-the-hash"],
    "pkinit-auth": ["ticket-lifecycle", "impacket-exec"],
    "rbcd": ["s4u-abuse", "computer-takeover"],
    "gpo-sysvol": ["gpo-abuse", "gpp-cpassword-hunt"],
    "coercion-map": ["coerce", "ntlm-relay"],
    "bloodhound-export": ["bloodhound-reconcile", "attack-paths"],
    "attack-paths": ["next-actions", "report", "campaign-analysis"],
}

_PREREQUISITES: dict[str, list[str]] = {}
for producer, consumers in _PRODUCERS.items():
    for consumer in consumers:
        _PREREQUISITES.setdefault(consumer, []).append(producer)


def capability_prerequisites(cap_id: str) -> dict[str, list[str]]:
    """Return best-run-after and produces-for hints for a capability."""
    best_after = [cid for cid in _PREREQUISITES.get(cap_id, []) if capability_registry.get(cid)]
    produces_for = [cid for cid in _PRODUCERS.get(cap_id, []) if capability_registry.get(cid)]
    return {
        "best_run_after": best_after,
        "produces_artifacts_for": produces_for,
    }


def evaluate_prerequisites(cap_id: str, *, session: Path | None = None) -> dict[str, Any]:
    """Evaluate prerequisite evidence without contacting a target.

    A missing session means prerequisites are unverified rather than blocked;
    this keeps planning useful before the first capability in an engagement.
    """
    # Use the declarative dependency map here even when this helper is called
    # before capability modules have completed import-time registration.
    required = sorted(set(_PREREQUISITES.get(cap_id, [])))
    seen: set[str] = set()
    if session is not None and Path(session).is_dir():
        events = Path(session) / "events.jsonl"
        if events.is_file():
            for line in events.read_text(encoding="utf-8").splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(event, dict) and event.get("capability"):
                    seen.add(str(event["capability"]))
        for producer in required:
            if (Path(session) / f"{producer}.json").is_file():
                seen.add(producer)
    satisfied = sorted(set(required) & seen)
    missing = sorted(set(required) - seen)
    if not required:
        status = "not-required"
    elif session is None:
        status = "unverified"
    elif missing:
        status = "missing"
    else:
        status = "satisfied"
    return {
        "required": required,
        "satisfied": satisfied,
        "missing": missing,
        "status": status,
        "remediation": [
            f"Run `{item}` first to produce prerequisite evidence." for item in missing
        ],
    }


def format_next_actions_block(
    cap: Capability, *, domain: str | None = None, dc_ip: str | None = None
) -> dict[str, Any]:
    """Build a human+JSON friendly next-actions payload after a successful run."""
    from adaf_attack.core.ux import build_ready_command, suggested_next_actions

    suggestions = suggested_next_actions(cap)
    commands: list[dict[str, str]] = []
    for cid in suggestions:
        follow = capability_registry.get(cid)
        if follow is None:
            continue
        cmd = build_ready_command(
            cid,
            domain=domain,
            dc_ip=dc_ip,
            force=bool(follow.destructive),
        )
        commands.append({"id": cid, "summary": follow.summary, "command": cmd})
    return {
        "after": cap.id,
        "suggestions": commands,
        "count": len(commands),
    }


def format_stages_progress(cap: Capability, current: str | None = None) -> dict[str, Any]:
    """Return ordered stages with optional current marker for progress UIs."""
    from adaf_attack.core.ux import stages_for_capability

    stages = stages_for_capability(cap)
    items = []
    reached_current = current is None
    for stage in stages:
        if current and stage == current:
            status = "active"
            reached_current = True
        elif not reached_current:
            status = "done"
        else:
            status = "pending"
        items.append({"id": stage, "status": status})
    return {"capability": cap.id, "stages": items, "current": current}


def session_findings_dashboard(
    session_dir: Path, *, severity: str | None = None, limit: int = 50
) -> dict[str, Any]:
    """Richer findings dashboard payload for CLI and TUI."""
    from adaf_attack.core.ux import session_findings_summary

    summary = session_findings_summary(session_dir)
    session_dir = Path(session_dir)
    findings_raw = _load_json(session_dir / "findings.json")
    interesting = _load_json(session_dir / "interesting.json")
    findings_list = findings_raw.get("findings") or []
    if not isinstance(findings_list, list):
        findings_list = []

    filtered: list[dict[str, Any]] = []
    severity_counts: dict[str, int] = {}
    triage_counts: dict[str, int] = {}
    for item in findings_list:
        if not isinstance(item, dict):
            continue
        sev = str(item.get("severity", "unknown")).lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        triage = str(item.get("status", "open")).lower()
        triage_counts[triage] = triage_counts.get(triage, 0) + 1
        if severity and sev != severity.lower():
            continue
        normalized = {
            "id": item.get("id") or item.get("finding_id"),
            "title": item.get("title") or item.get("name") or "untitled",
            "severity": sev,
            "category": item.get("category") or item.get("tactic"),
        }
        # Keep the stable minimal shape for legacy findings while preserving
        # triage metadata for records that actually carry it.
        if "status" in item:
            normalized["status"] = str(item["status"]).lower()
        for key in ("owner", "tags", "triage_note", "comment"):
            if key in item:
                normalized[key] = item[key]
        filtered.append(normalized)
        if len(filtered) >= limit:
            break

    top_paths = interesting.get("top_paths") or []
    if not isinstance(top_paths, list):
        top_paths = []

    return {
        **summary,
        "findings": filtered,
        "severity_counts": severity_counts,
        "triage_counts": triage_counts,
        "top_paths": top_paths[:10],
        "filter": {"severity": severity, "limit": limit},
    }


def export_plan_markdown(
    *,
    capability_id: str,
    domain: str,
    dc_ip: str,
    risk: dict[str, Any],
    checklist: dict[str, Any],
    ready_command: str,
    prerequisites: dict[str, list[str]] | None = None,
) -> str:
    """Render a shareable plan/review markdown document."""
    lines = [
        f"# ADAF-ATTACK plan: `{capability_id}`",
        "",
        f"- **Target:** `{domain}` @ `{dc_ip}`",
        f"- **Risk level:** {risk.get('level', 'unknown')}",
        f"- **May modify target:** {risk.get('may_modify_target', False)}",
        f"- **Requires --force:** {risk.get('requires_force', False)}",
        f"- **Force provided:** {risk.get('force_provided', False)}",
        "",
        "## Opsec",
        "",
        checklist.get("opsec_hint") or "Standard opsec applies.",
        "",
        "## Pre-flight checklist",
        "",
    ]
    for item in checklist.get("items") or []:
        mark = "[ ]"
        lines.append(f"- {mark} {item.get('label')}")
    if prerequisites:
        lines.extend(["", "## Prerequisites / producers", ""])
        best = prerequisites.get("best_run_after") or []
        produces = prerequisites.get("produces_artifacts_for") or []
        if best:
            lines.append(f"- **Best run after:** {', '.join(f'`{x}`' for x in best)}")
        if produces:
            lines.append(f"- **Produces artifacts for:** {', '.join(f'`{x}`' for x in produces)}")
    lines.extend(
        [
            "",
            "## Copy-ready command",
            "",
            "```bash",
            ready_command,
            "```",
            "",
            "_Generated by ADAF-ATTACK. Review scope and authorization before execution._",
            "",
        ]
    )
    return "\n".join(lines)
