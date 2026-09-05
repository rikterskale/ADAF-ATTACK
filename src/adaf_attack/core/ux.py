"""Operator UX helpers for the 15 enhancements.

Phase grouping, risk checklists, progress stages, session previews/diff,
unified search, guided tour, copy-ready commands, next-actions, and
opsec indicators.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, cast

from adaf_attack.core.capability_help_data import capability_option_spec
from adaf_attack.core.command_templates import render_command
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import Capability, capability_registry

_READY_COMMAND_KWARG_FLAGS = frozenset({"--domain", "--dc-ip", "--username", "--force"})

# ---------------------------------------------------------------------------
# 1. Kill-chain phase labels & grouping
# ---------------------------------------------------------------------------

PHASE_LABELS: dict[str, str] = {
    "discovery": "1. Discovery",
    "enumeration": "2. Enumeration",
    "credential-access": "3. Credential Access",
    "privilege-escalation": "4. Privilege Escalation",
    "lateral-movement": "5. Lateral Movement",
    "analysis": "6. Analysis",
    "export": "7. Export / Reporting",
    "general": "Other",
}

# Map registry categories → kill-chain phase keys
_CATEGORY_TO_PHASE: dict[str, str] = {
    "discovery": "discovery",
    "enumeration": "enumeration",
    "credential-access": "credential-access",
    "privilege-escalation": "privilege-escalation",
    "lateral-movement": "lateral-movement",
    "analysis": "analysis",
    "export": "export",
    "general": "general",
}


def capability_phase(cap: Capability) -> str:
    """Return the kill-chain phase key for a capability."""
    return _CATEGORY_TO_PHASE.get(cap.category, "general")


def group_capabilities_by_phase() -> dict[str, list[Capability]]:
    """Group all registered capabilities by kill-chain phase (ordered)."""
    groups: dict[str, list[Capability]] = defaultdict(list)
    for cap in capability_registry.list():
        groups[capability_phase(cap)].append(cap)
    # Preserve a stable order matching PHASE_LABELS
    ordered: dict[str, list[Capability]] = {}
    for key in PHASE_LABELS:
        if key in groups:
            ordered[key] = sorted(groups[key], key=lambda c: c.id)
    # Any unexpected phase keys last
    for key, caps in groups.items():
        if key not in ordered:
            ordered[key] = sorted(caps, key=lambda c: c.id)
    return ordered


# ---------------------------------------------------------------------------
# 2 / 12. Risk checklist + opsec indicators
# ---------------------------------------------------------------------------


def risk_checklist(cap: Capability) -> dict[str, Any]:
    """Return a structured risk / pre-flight checklist for a capability."""
    phase = capability_phase(cap)
    requires_domain_user = phase in {
        "enumeration",
        "credential-access",
        "privilege-escalation",
        "lateral-movement",
    } or cap.category in {"enumeration", "credential-access"}
    requires_force = cap.requires_force
    network_contact = bool(cap.safety and cap.safety.network_side_effect) or phase not in {
        "analysis",
        "export",
    }
    may_modify = bool(cap.safety and cap.safety.modifies_directory)

    from adaf_attack.core.registry import ApprovalPolicy

    items = [
        {"id": "scope", "label": "Engagement scope confirmed", "required": True},
        {
            "id": "auth",
            "label": "Valid credentials / ticket available",
            "required": requires_domain_user,
        },
        {
            "id": "force",
            "label": "--force supplied for approved side effect",
            "required": requires_force,
        },
        {
            "id": "opsec",
            "label": "Opsec profile reviewed (stealth/balanced/loud)",
            "required": True,
        },
        {"id": "rollback", "label": "Cleanup / rollback path identified", "required": may_modify},
    ]
    if cap.safety and cap.safety.approval == ApprovalPolicy.SCOPED_TOKEN:
        items.append(
            {
                "id": "approval_token",
                "label": "--approval-token with matching --engagement-id",
                "required": True,
            }
        )
    return {
        "id": cap.id,
        "phase": phase,
        "phase_label": PHASE_LABELS.get(phase, phase),
        "destructive": cap.destructive,
        "safety": cap.safety.as_dict() if cap.safety else {},
        "requires_domain_user": requires_domain_user,
        "requires_force": requires_force,
        "network_contact": network_contact,
        "may_modify_target": may_modify,
        "items": items,
        "opsec_hint": (
            "Prefer stealth profile; avoid loud credential dumping unless approved."
            if phase in {"credential-access", "privilege-escalation"}
            else "Standard opsec applies."
        ),
    }


def operator_approvals(cap: Capability) -> list[str]:
    """Return the explicit approvals an operator must satisfy before running."""
    safety = cap.safety
    if safety is None:
        return ["Review plan output before any live run"]
    approvals: list[str] = []
    if safety.requires_force:
        approvals.append("--force")
    if safety.requires_ack:
        approvals.append("--i-understand (first use in workspace)")
    if safety.approval.value == "scoped_token":
        approvals.append("--approval-token with matching --engagement-id")
    if not approvals and safety.network_side_effect:
        approvals.append("Written authorization for the target scope")
    return approvals


ROLLBACK_COMMAND_TEMPLATE = (
    "adaf-attack rollback --session <session> --domain <domain> --dc-ip <dc-ip> --force"
)
NOT_ROLLED_BACK = (
    "Tickets, hashes, captured secrets, and detection telemetry are not reversed. "
    "Automatic rollback only reverses mutations recorded in session cleanup.json."
)


def operator_rollback_contract(cap: Capability) -> dict[str, str]:
    """Return rollback class, implication, command, and exclusions for operators."""
    safety = cap.safety
    rollback = safety.rollback.value if safety is not None else "manual"
    if rollback == "automatic":
        implication = (
            "Mutations record pre-state in session cleanup.json; "
            "use `adaf-attack rollback` (alias of `cleanup`)."
        )
    elif rollback == "manual":
        implication = "Operator must verify and reverse residual effects on the authorized target."
    else:
        implication = "No automatic rollback; treat as read/observe or advisory."
    return {
        "rollback": rollback,
        "rollback_implication": implication,
        "rollback_command": ROLLBACK_COMMAND_TEMPLATE,
        "not_rolled_back": NOT_ROLLED_BACK,
    }


def destructive_confirmation_copy(
    cap: Capability,
    *,
    domain: str,
    dc_ip: str,
) -> str:
    """Operator-facing destructive confirmation, including rollback exclusions."""
    rollback = operator_rollback_contract(cap)
    risk = (
        str(cap.safety.risk.value).upper()
        if cap.safety
        else ("DESTRUCTIVE" if cap.destructive else "OBSERVE")
    )
    return (
        f"DESTRUCTIVE {cap.id} against {domain} @ {dc_ip}\n"
        f"This may modify the target. Risk: {risk}. "
        "Re-run with --yes to skip this prompt.\n"
        f"Rollback command: {rollback['rollback_command']}\n"
        f"Not rolled back: {rollback['not_rolled_back']}"
    )


def operator_capability_contract(cap: Capability) -> dict[str, Any]:
    """Self-explaining contract shared by capability-help, explain, plan, and review."""
    from adaf_attack.core.ux_extra import capability_prerequisites, format_stages_progress

    spec = capability_option_spec(cap.id, cap.requires_force)
    checklist = risk_checklist(cap)
    prerequisites = capability_prerequisites(cap.id)
    rollback = operator_rollback_contract(cap)
    required_params = [option[3:] for option in spec.required if option.startswith("-P ")]
    evidence_produced = ["session.json", "events.jsonl", "findings.json"]
    if "graph" in (cap.tags or ()) or capability_phase(cap) in {
        "discovery",
        "enumeration",
        "analysis",
    }:
        evidence_produced.append("graph.json")
    if cap.fixture:
        evidence_produced.append(str(cap.fixture))
    if cap.safety and cap.safety.modifies_directory:
        evidence_produced.append("cleanup.json (rollback pre-state)")
    for downstream in prerequisites.get("produces_artifacts_for") or []:
        label = f"evidence for {downstream}"
        if label not in evidence_produced:
            evidence_produced.append(label)
    return {
        "id": cap.id,
        "risk": (
            str(cap.safety.risk.value).upper()
            if cap.safety
            else ("DESTRUCTIVE" if cap.destructive else "OBSERVE")
        ),
        "approvals": operator_approvals(cap),
        "rollback": rollback["rollback"],
        "rollback_implication": rollback["rollback_implication"],
        "rollback_command": rollback["rollback_command"],
        "not_rolled_back": rollback["not_rolled_back"],
        "required_options": list(spec.required),
        "optional_options": list(spec.optional),
        "required_params": required_params,
        "prerequisites": prerequisites,
        "evidence_produced": evidence_produced,
        "stages": format_stages_progress(cap)["stages"],
        "preflight_checklist": checklist,
        "copy_ready_command": build_ready_command(
            cap.id,
            force=cap.requires_force,
            include_required_placeholders=True,
        ),
        "after_run_command": f"adaf-attack what-next {cap.id}",
    }


# ---------------------------------------------------------------------------
# 13. Copy-ready command generation
# ---------------------------------------------------------------------------


def build_ready_command(
    capability_id: str,
    *,
    domain: str | None = None,
    dc_ip: str | None = None,
    username: str | None = None,
    force: bool = False,
    extra: dict[str, str] | None = None,
    include_required_placeholders: bool = True,
) -> str:
    """Build a copy-pasteable CLI invocation.

    When ``include_required_placeholders`` is true (default), required options
    from ``capability_option_spec`` that were not supplied are appended as
    clear placeholders (``--set-on <set-on>``, ``-P sam=<user>``, etc.) so
    ``capability-help``, ``plan``, and TUI copy-ready commands stay complete.
    """
    return render_command(
        build_ready_argv(
            capability_id,
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            force=force,
            extra=extra,
            include_required_placeholders=include_required_placeholders,
        )
    )


def build_ready_argv(
    capability_id: str,
    *,
    domain: str | None = None,
    dc_ip: str | None = None,
    username: str | None = None,
    force: bool = False,
    extra: dict[str, str] | None = None,
    include_required_placeholders: bool = True,
) -> list[str]:
    """Build the unquoted argument vector behind a copy-ready command."""
    parts = ["adaf-attack", "run", capability_id]
    if domain:
        parts.extend(["--domain", domain])
    if dc_ip:
        parts.extend(["--dc-ip", dc_ip])
    if username:
        parts.extend(["--username", username])
    if force:
        parts.append("--force")

    provided_params = {str(k) for k in (extra or {})}
    emitted_flags: set[str] = set()
    if domain:
        emitted_flags.add("--domain")
    if dc_ip:
        emitted_flags.add("--dc-ip")
    if username:
        emitted_flags.add("--username")
    if force:
        emitted_flags.add("--force")

    if include_required_placeholders:
        spec = capability_option_spec(capability_id, force)
        for option in spec.required:
            if option == "--force":
                if "--force" not in emitted_flags:
                    parts.append("--force")
                    emitted_flags.add("--force")
                continue
            if option.startswith("-P "):
                remainder = option[3:]
                key, _, sample = remainder.partition("=")
                if key in provided_params:
                    continue
                placeholder = f"{key}={sample or 'VALUE'}"
                parts.extend(["-P", placeholder])
                provided_params.add(key)
                continue
            if option.startswith("--"):
                flag = option.split("=", 1)[0]
                if flag in emitted_flags:
                    continue
                if flag == "--domain":
                    parts.extend(["--domain", domain or "<domain>"])
                    emitted_flags.add(flag)
                    continue
                if flag == "--dc-ip":
                    parts.extend(["--dc-ip", dc_ip or "<dc-ip>"])
                    emitted_flags.add(flag)
                    continue
                if flag == "--username":
                    parts.extend(["--username", username or "<username>"])
                    emitted_flags.add(flag)
                    continue
                name = flag.lstrip("-").replace("-", "_")
                parts.extend([flag, f"<{name}>"])
                emitted_flags.add(flag)

    if extra:
        for key, value in extra.items():
            parts.extend(["-P", f"{key}={value}"])
    return parts


# ---------------------------------------------------------------------------
# 3. Structured progress stages
# ---------------------------------------------------------------------------


def stages_for_capability(cap: Capability) -> list[str]:
    """Return ordered progress stage names for a capability run."""
    specialized = {
        "esc-chain": ["prepare", "select-template", "enroll", "pkinit", "next-actions"],
        "rbcd-ticket-workflow": ["prepare", "set-rbcd", "s4u", "ticket", "next-actions"],
        "shadow-pkinit-workflow": ["prepare", "write-shadow", "pkinit", "next-actions"],
        "unpac-the-hash": ["prepare", "pkinit", "u2u-pac", "recover-hash", "next-actions"],
        "dcshadow": ["prepare", "plant-objects", "register-spns", "drsuapi-push", "next-actions"],
        "golden-cert": ["prepare", "forge", "export-pfx", "next-actions"],
        "pkinit-auth": ["prepare", "load-cert", "pkinit", "export-ccache", "next-actions"],
    }
    if cap.id in specialized:
        return list(specialized[cap.id])
    base = ["prepare", "connect", "execute"]
    phase = capability_phase(cap)
    if phase in {"credential-access", "privilege-escalation"}:
        base.append("harvest")
    if phase in {"analysis", "export"} or "graph" in (cap.tags or ()):
        base.append("analyze")
    base.append("next-actions")
    return base


# ---------------------------------------------------------------------------
# 4 / 8. Session findings preview + summary
# ---------------------------------------------------------------------------


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return cast(dict[str, Any], value) if isinstance(value, dict) else {}
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}


def session_findings_summary(session_dir: Path) -> dict[str, Any]:
    """Lightweight findings + graph summary for a session directory."""
    session_dir = Path(session_dir)
    meta = _load_json(session_dir / "session.json")
    findings_raw = _load_json(session_dir / "findings.json")
    graph_raw = _load_json(session_dir / "graph.json")

    findings_list = findings_raw.get("findings") or []
    if not isinstance(findings_list, list):
        findings_list = []

    severity_counts: dict[str, int] = defaultdict(int)
    titles: list[str] = []
    for f in findings_list:
        if isinstance(f, dict):
            sev = str(f.get("severity", "unknown")).lower()
            severity_counts[sev] += 1
            title = f.get("title") or f.get("id") or "untitled"
            titles.append(str(title))

    graph_summary = graph_raw.get("summary") or {}
    nodes = int(graph_summary.get("nodes") or 0)
    edges = int(graph_summary.get("edges") or 0)

    return {
        "session_id": meta.get("session_id") or session_dir.name,
        "created_at": meta.get("created_at"),
        "finding_count": len(findings_list),
        "severity": dict(severity_counts),
        "titles": titles[:20],
        "graph": {"nodes": nodes, "edges": edges},
        "path": str(session_dir),
    }


# ---------------------------------------------------------------------------
# 14. Session diff
# ---------------------------------------------------------------------------


def diff_sessions(a: Path, b: Path) -> dict[str, Any]:
    """Compare findings and evidence-backed graph relationships between sessions."""
    sa = session_findings_summary(a)
    sb = session_findings_summary(b)

    def _finding_map(path: Path) -> dict[str, dict[str, Any]]:
        payload = _load_json(Path(path) / "findings.json")
        values = payload.get("findings") if isinstance(payload, dict) else []
        if not isinstance(values, list):
            return {}
        result: dict[str, dict[str, Any]] = {}
        for value in values:
            if not isinstance(value, dict):
                continue
            key = str(value.get("id") or value.get("finding_id") or value.get("title") or "")
            if key:
                result[key] = value
        return result

    findings_a = _finding_map(a)
    findings_b = _finding_map(b)
    added = sorted(set(findings_b) - set(findings_a))
    removed = sorted(set(findings_a) - set(findings_b))
    severity_delta: dict[str, int] = {}
    for values, sign in ((findings_b.values(), 1), (findings_a.values(), -1)):
        for value in values:
            severity = str(value.get("severity", "unknown")).lower()
            severity_delta[severity] = severity_delta.get(severity, 0) + sign

    def _graph_relationships(path: Path) -> dict[str, dict[str, Any]]:
        raw = _load_json(Path(path) / "graph.json")
        edges = raw.get("edges") if isinstance(raw, dict) else []
        if not isinstance(edges, list):
            return {}
        result: dict[str, dict[str, Any]] = {}
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            source = str(edge.get("source") or "")
            target = str(edge.get("target") or "")
            relation = str(edge.get("kind") or "Default")
            if not source or not target:
                continue
            key = json.dumps(
                {
                    "source": source,
                    "target": target,
                    "relation": relation,
                    "properties": edge.get("properties") or {},
                },
                sort_keys=True,
                default=str,
            )
            result[key] = {
                "source": source,
                "target": target,
                "relation": relation,
                "properties": edge.get("properties") or {},
            }
        return result

    relationships_a = _graph_relationships(a)
    relationships_b = _graph_relationships(b)
    relationships_added = [
        relationships_b[key] for key in sorted(set(relationships_b) - set(relationships_a))
    ]
    relationships_removed = [
        relationships_a[key] for key in sorted(set(relationships_a) - set(relationships_b))
    ]
    return {
        "a": {
            "session_id": sa["session_id"],
            "findings": sa["finding_count"],
            "nodes": sa["graph"]["nodes"],
        },
        "b": {
            "session_id": sb["session_id"],
            "findings": sb["finding_count"],
            "nodes": sb["graph"]["nodes"],
        },
        "finding_delta": sb["finding_count"] - sa["finding_count"],
        "node_delta": sb["graph"]["nodes"] - sa["graph"]["nodes"],
        "edge_delta": sb["graph"]["edges"] - sa["graph"]["edges"],
        "findings_added": added,
        "findings_removed": removed,
        "severity_delta": {key: value for key, value in sorted(severity_delta.items()) if value},
        "relationships_added": relationships_added,
        "relationships_removed": relationships_removed,
        "attack_paths_changed": bool(relationships_added or relationships_removed),
    }


# ---------------------------------------------------------------------------
# 9. Unified search
# ---------------------------------------------------------------------------


def unified_search(query: str, *, session: Path | None = None, limit: int = 25) -> dict[str, Any]:
    """Search capabilities and, optionally, persisted engagement evidence.

    Results are ranked deterministically: exact identifiers first, then title
    and description matches, with stable type/id tie-breakers.
    """
    q = (query or "").strip().lower()
    caps: list[dict[str, Any]] = []
    if not q:
        return {"query": query, "capabilities": [], "count": 0}

    for cap in capability_registry.list():
        hay = " ".join(
            [
                cap.id,
                cap.summary,
                cap.category,
                " ".join(cap.tags or ()),
                cap.safety.risk.value if cap.safety and cap.requires_force else "",
            ]
        ).lower()
        if q in hay:
            caps.append(
                {
                    "id": cap.id,
                    "category": cap.category,
                    "phase": capability_phase(cap),
                    "summary": cap.summary,
                    "destructive": cap.destructive,
                    "safety": cap.safety.as_dict() if cap.safety else {},
                }
            )
    results: list[dict[str, Any]] = [
        {
            "type": "capability",
            "id": item["id"],
            "title": item["id"],
            "summary": item["summary"],
            "score": 100 if item["id"].lower() == q else 60,
            "data": item,
        }
        for item in caps
    ]
    if session is not None:
        session = Path(session)
        if session.is_dir():
            findings = _load_json(session / "findings.json").get("findings") or []
            if isinstance(findings, list):
                for item in findings:
                    if not isinstance(item, dict):
                        continue
                    text = " ".join(
                        str(item.get(key, ""))
                        for key in ("id", "title", "category", "evidence", "asset")
                    )
                    if q in text.lower():
                        finding_id = str(item.get("id") or "").lower()
                        finding_title = str(item.get("title") or "").lower()
                        results.append(
                            {
                                "type": "finding",
                                "id": item.get("id") or item.get("title") or "finding",
                                "title": item.get("title") or item.get("id") or "finding",
                                "summary": item.get("evidence")
                                or item.get("category")
                                or "saved finding",
                                "score": (
                                    90
                                    if finding_id == q
                                    else 85
                                    if finding_id.startswith(q) or finding_title.startswith(q)
                                    else 50
                                ),
                                "data": item,
                            }
                        )
        graph_path = session / "graph.json"
        if graph_path.is_file():
            try:
                graph = AttackGraph.from_file(graph_path)
            except (OSError, KeyError, TypeError, ValueError):
                graph = None
            if graph is not None:
                for node in graph.nodes.values():
                    text = " ".join(
                        (node.id, node.kind, *(str(v) for v in node.properties.values()))
                    )
                    if q in text.lower():
                        results.append(
                            {
                                "type": "asset"
                                if node.kind in {"Computer", "Domain"}
                                else "identity",
                                "id": node.id,
                                "title": node.properties.get("sam") or node.id,
                                "summary": f"{node.kind} in the engagement graph",
                                "score": 45,
                                "data": {"kind": node.kind, "properties": node.properties},
                            }
                        )
                for position, edge in enumerate(graph.edges):
                    text = f"{edge.source} {edge.kind} {edge.target}"
                    if q in text.lower():
                        results.append(
                            {
                                "type": "attack_path",
                                "id": f"edge-{position}",
                                "title": f"{edge.source} --{edge.kind}--> {edge.target}",
                                "summary": "Evidence-backed graph relationship",
                                "score": 40,
                                "data": {
                                    "source": edge.source,
                                    "target": edge.target,
                                    "relation": edge.kind,
                                    "properties": edge.properties,
                                },
                            }
                        )
            try:
                artifacts = sorted(
                    artifact_path.name
                    for artifact_path in session.iterdir()
                    if artifact_path.is_file()
                )
            except OSError:
                artifacts = []
            for artifact in artifacts:
                if q in artifact.lower() and not any(item["id"] == artifact for item in results):
                    results.append(
                        {
                            "type": "evidence",
                            "id": artifact,
                            "title": artifact,
                            "summary": "Persisted engagement artifact",
                            "score": 80 if artifact.lower().startswith(q) else 20,
                            "data": {"path": str(session / artifact)},
                        }
                    )
    results.sort(key=lambda item: (-int(item["score"]), str(item["type"]), str(item["id"])))
    results = results[: max(1, limit)]
    return {
        "query": query,
        "capabilities": [item["data"] for item in results if item["type"] == "capability"],
        "results": results,
        "count": len(results),
        "session": str(session) if session is not None else None,
    }


# ---------------------------------------------------------------------------
# 5. Next-actions suggestions
# ---------------------------------------------------------------------------

_NEXT_BY_PHASE: dict[str, list[str]] = {
    "discovery": ["ldap-enum", "trusts-enum", "coercion-map"],
    "enumeration": ["acl-enum", "adcs-enum", "gmsa-laps-enum", "asrep-roast"],
    "credential-access": ["kerberoast", "dcsync", "shadow-creds", "pkinit-auth"],
    "privilege-escalation": ["rbcd", "gpo-abuse", "esc-chain", "computer-takeover"],
    "lateral-movement": ["impacket-exec", "ntlm-relay", "s4u-abuse"],
    "analysis": ["attack-paths", "next-actions", "campaign-analysis", "report"],
    "export": ["bloodhound-export", "report", "identity-bridge"],
}


def suggested_next_actions(cap: Capability, *, limit: int = 5) -> list[str]:
    """Suggest logical follow-on capability IDs after running *cap*."""
    phase = capability_phase(cap)
    candidates = list(_NEXT_BY_PHASE.get(phase, []))
    # Prefer same-phase then next phase
    order = list(PHASE_LABELS.keys())
    try:
        idx = order.index(phase)
        for later in order[idx + 1 :]:
            candidates.extend(_NEXT_BY_PHASE.get(later, [])[:2])
    except ValueError:
        pass
    # Deduplicate while preserving order, skip self
    seen: set[str] = {cap.id}
    out: list[str] = []
    for cid in candidates:
        if cid not in seen and capability_registry.get(cid) is not None:
            seen.add(cid)
            out.append(cid)
            if len(out) >= limit:
                break
    return out


# ---------------------------------------------------------------------------
# 15. Guided tour
# ---------------------------------------------------------------------------


def guided_tour_payload() -> dict[str, Any]:
    """Return the interactive guided-tour steps for new operators."""
    steps = [
        {
            "id": "guide",
            "title": "Check your current stage",
            "command": "adaf-attack guide",
            "why": "One authoritative command for current stage, blockers, and the exact next step.",
        },
        {
            "id": "doctor",
            "title": "Check local environment",
            "command": "adaf-attack doctor --profile user-readiness --explain",
            "why": "Verify Python, optional deps (impacket, textual), and workspace paths.",
        },
        {
            "id": "demo",
            "title": "Offline first success (no network)",
            "command": "adaf-attack quickstart --workspace ./quickstart",
            "why": "Materialize the packaged demo session and open a findings dashboard without contacting a target.",
        },
        {
            "id": "list",
            "title": "Browse capabilities by kill-chain phase",
            "command": "adaf-attack list-capabilities --by-phase",
            "why": "See the full toolkit organized the way red-teamers think.",
        },
        {
            "id": "help",
            "title": "Inspect a capability risk checklist",
            "command": "adaf-attack capability-help ldap-enum",
            "why": "Every capability shows required options, risk items, and a copy-ready command.",
        },
        {
            "id": "plan",
            "title": "Preview a run without touching the target",
            "command": "adaf-attack plan ldap-enum -d corp.example --dc-ip 10.0.0.10",
            "why": "Plan shows opsec profile, stages, and the exact command you will execute.",
        },
        {
            "id": "profile",
            "title": "Save a named target profile",
            "command": "adaf-attack profile set engagement --domain corp.example --dc-ip 10.0.0.10 --opsec stealth --default",
            "why": "Profiles keep domain, DC, and opsec settings so you type less on subsequent runs.",
        },
        {
            "id": "search",
            "title": "Search the capability surface",
            "command": "adaf-attack search kerberoast",
            "why": "Free-text search across IDs, summaries, categories, and tags.",
        },
        {
            "id": "tui",
            "title": "Launch the interactive TUI (optional)",
            "command": "adaf-attack start",
            "why": "Sidebar phase labels, live findings, and review-first execution.",
        },
        {
            "id": "sessions",
            "title": "Inspect past sessions and findings",
            "command": "adaf-attack sessions --limit 5",
            "why": "Every run leaves a session; use findings preview and session diff later.",
        },
    ]
    return {
        "title": "ADAF-ATTACK guided tour",
        "steps": steps,
        "next_step": "Run the first command: adaf-attack guide",
    }


# ---------------------------------------------------------------------------
# Convenience: human phase label lookup
# ---------------------------------------------------------------------------


def phase_label(phase_key: str) -> str:
    return PHASE_LABELS.get(phase_key, phase_key)


# Re-export extended helpers (kept in ux_extra to ease incremental deploys)
from adaf_attack.core.ux_extra import (  # noqa: E402  # intentional late re-export
    advance_stage_from_log,
    capability_dependency_graph,
    capability_prerequisites,
    evaluate_prerequisites,
    export_plan_markdown,
    format_next_actions_block,
    format_stages_progress,
    session_findings_dashboard,
)

__all__ = [
    "NOT_ROLLED_BACK",
    "PHASE_LABELS",
    "ROLLBACK_COMMAND_TEMPLATE",
    "advance_stage_from_log",
    "build_ready_command",
    "capability_dependency_graph",
    "capability_phase",
    "capability_prerequisites",
    "destructive_confirmation_copy",
    "diff_sessions",
    "evaluate_prerequisites",
    "export_plan_markdown",
    "format_next_actions_block",
    "format_stages_progress",
    "group_capabilities_by_phase",
    "guided_tour_payload",
    "operator_approvals",
    "operator_capability_contract",
    "operator_rollback_contract",
    "phase_label",
    "risk_checklist",
    "session_findings_dashboard",
    "session_findings_summary",
    "stages_for_capability",
    "suggested_next_actions",
    "unified_search",
]
