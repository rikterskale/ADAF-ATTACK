"""Unified operator journey: one authoritative next step from install to closeout.

CLI, TUI, and installers share this composer so ``adaf-attack guide``,
``workflow next``, and the TUI journey panel always recommend the same
copy-ready command for the current stage.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from adaf_attack.core.paths import default_workspace_dir
from adaf_attack.core.user_config import load_user_config
from adaf_attack.core.workflow_engine import (
    PHASES,
    WorkflowAction,
    WorkflowEngine,
    WorkflowError,
)

STAGE_LABELS: dict[str, str] = {
    "install-blocked": "Install readiness",
    "first-success": "Safe offline first success",
    "orient": "Authorize scope",
    "discover": "Baseline discovery",
    "operate": "Finding-driven operations",
    "deliver": "Reporting and packaging",
    "closeout": "Engagement closeout",
    "complete": "Complete",
}

STAGE_PROGRESS: dict[str, float] = {
    "install-blocked": 0.0,
    "first-success": 10.0,
    "orient": 25.0,
    "discover": 40.0,
    "operate": 60.0,
    "deliver": 85.0,
    "closeout": 95.0,
    "complete": 100.0,
}

# Workflow bookkeeping actions that ``guide --advance`` may complete offline.
SAFE_ADVANCE_ACTIONS = frozenset(
    {
        "authorize-scope",
        "run-discovery",
        "generate-report",
    }
)


@dataclass(frozen=True)
class JourneyAction:
    """One concrete next step the operator can copy or advance."""

    id: str
    title: str
    why: str
    suggested_command: str
    kind: str = "required"
    unlock_conditions: list[str] = field(default_factory=list)
    advance_safe: bool = False

    def document(self) -> dict[str, Any]:
        return asdict(self)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}


def _target_defaults() -> dict[str, str | None]:
    """Resolve domain/dc/username from user config or the default profile."""
    config = load_user_config()
    domain = config.get("target.domain")
    dc_ip = config.get("target.dc_ip")
    username = config.get("target.username")
    default_name = config.get("profile.default")
    if isinstance(default_name, str) and default_name and (not domain or not dc_ip):
        try:
            from adaf_attack.core.profiles import get_profile

            profile = get_profile(default_name) or {}
        except (OSError, ValueError):
            profile = {}
        domain = domain or profile.get("domain")
        dc_ip = dc_ip or profile.get("dc_ip")
        username = username or profile.get("username")
    return {
        "domain": str(domain) if domain else None,
        "dc_ip": str(dc_ip) if dc_ip else None,
        "username": str(username) if username else None,
    }


def suggested_command_for_action(
    action: WorkflowAction,
    *,
    session: Path | None = None,
    workspace: Path | None = None,
) -> str:
    """Return a copy-ready CLI invocation for a workflow action."""
    workspace_flag = f" --workspace {workspace}" if workspace is not None else ""
    action_id = action.id
    if action_id == "authorize-scope":
        return f"adaf-attack workflow authorize{workspace_flag}".strip()
    if action_id == "run-discovery":
        defaults = _target_defaults()
        if defaults["domain"] and defaults["dc_ip"]:
            from adaf_attack.core.ux import build_ready_command

            return build_ready_command(
                action.capability_id or "ldap-enum",
                domain=defaults["domain"],
                dc_ip=defaults["dc_ip"],
                username=defaults["username"],
                include_required_placeholders=True,
            )
        return f"adaf-attack workflow do run-discovery{workspace_flag}".strip()
    if action_id.startswith("validate:"):
        return f"adaf-attack workflow do {action_id}{workspace_flag}".strip()
    if action_id.startswith("decision:"):
        return (
            f"adaf-attack workflow decide {action_id} mitigate "
            f'--rationale "owner approved"{workspace_flag}'
        ).strip()
    if action_id.startswith(("response:", "verify:")):
        return f"adaf-attack workflow do {action_id}{workspace_flag}".strip()
    if action_id.startswith("mitigate:"):
        finding_id = action_id.split(":", 1)[1]
        return (
            f"adaf-attack workflow transition {finding_id} mitigated "
            f'--note "remediation recorded"{workspace_flag}'
        ).strip()
    if action_id == "generate-report":
        if session is not None:
            return (
                f"adaf-attack engagement report --session {session} --engagement-id ENGAGEMENT-001"
            )
        return f"adaf-attack workflow do generate-report{workspace_flag}".strip()
    if action.capability_id:
        defaults = _target_defaults()
        from adaf_attack.core.ux import build_ready_command

        return build_ready_command(
            action.capability_id,
            domain=defaults["domain"],
            dc_ip=defaults["dc_ip"],
            username=defaults["username"],
            include_required_placeholders=True,
        )
    return f"adaf-attack workflow do {action_id}{workspace_flag}".strip()


def action_is_advance_safe(action: WorkflowAction) -> bool:
    """Return whether ``guide --advance`` may complete this action offline."""
    # Decisions and live capability runs stay review-first.
    return action.id in SAFE_ADVANCE_ACTIONS or action.id.startswith(
        ("validate:", "response:", "verify:")
    )


def enrich_action(
    action: WorkflowAction,
    *,
    session: Path | None = None,
    workspace: Path | None = None,
) -> dict[str, Any]:
    """Serialize a workflow action with a copy-ready suggested_command."""
    command = suggested_command_for_action(action, session=session, workspace=workspace)
    return {
        "id": action.id,
        "kind": action.kind,
        "title": action.title,
        "description": action.description,
        "phase": action.phase,
        "consequence": action.consequence,
        "capability_id": action.capability_id,
        "finding_ids": list(action.finding_ids),
        "unlock_conditions": list(action.unlock_conditions),
        "priority": action.priority,
        "suggested_command": command,
        "advance_safe": action_is_advance_safe(action),
    }


def find_demo_session(workspace: Path) -> Path | None:
    """Locate a packaged demo/quickstart session under the workspace tree."""
    candidates = [
        workspace / "quickstart" / "demo-session",
        workspace / "demo-session",
        workspace / "demo" / "demo-session",
    ]
    for path in candidates:
        if (path / "session.json").is_file():
            meta = _load_json(path / "session.json")
            if meta.get("demo") or path.name == "demo-session":
                return path
    # Fall back to any session.json marked demo=true one level deep.
    if workspace.is_dir():
        try:
            for child in sorted(workspace.iterdir()):
                session_json = child / "session.json"
                if session_json.is_file() and _load_json(session_json).get("demo"):
                    return child
                nested = child / "demo-session" / "session.json"
                if nested.is_file():
                    return nested.parent
        except OSError:
            return None
    return None


def find_recent_session(workspace: Path) -> Path | None:
    """Best-effort most recently modified session directory with session.json."""
    demo = find_demo_session(workspace)
    if demo is not None:
        return demo
    if not workspace.is_dir():
        return None
    newest: Path | None = None
    newest_mtime = -1.0
    try:
        for child in workspace.iterdir():
            if not child.is_dir():
                continue
            marker = child / "session.json"
            if not marker.is_file():
                continue
            try:
                mtime = marker.stat().st_mtime
            except OSError:
                continue
            if mtime > newest_mtime:
                newest = child
                newest_mtime = mtime
    except OSError:
        return None
    return newest


def _packaged_demo_ready() -> tuple[bool, str | None]:
    try:
        from importlib.resources import files

        demo_files = files("adaf_attack.demo_data")
        missing = [
            name
            for name in ("acl-enum.json", "adcs-enum.json")
            if not demo_files.joinpath(name).is_file()
        ]
    except (ImportError, ModuleNotFoundError, OSError) as exc:
        return False, str(exc)
    if missing:
        return False, f"Missing packaged demo fixtures: {', '.join(missing)}"
    return True, None


def _doctor_blockers(doctor: dict[str, Any] | None) -> list[dict[str, str]]:
    if doctor is None:
        ready, detail = _packaged_demo_ready()
        if ready:
            return []
        return [
            {
                "id": "packaged-demo",
                "message": detail or "Packaged demo fixtures are missing.",
                "remediation": "Reinstall the release artifact, then rerun `adaf-attack doctor --profile user-readiness --explain`.",
                "suggested_command": "adaf-attack doctor --profile user-readiness --explain",
            }
        ]
    blockers: list[dict[str, str]] = []
    for check in doctor.get("checks") or []:
        if not isinstance(check, dict) or check.get("status") != "error":
            continue
        remediation = str(check.get("remediation") or "Run `adaf-attack doctor --explain`.")
        command = "adaf-attack doctor --profile user-readiness --explain"
        if "paths" in remediation or check.get("id") in {"data_dir", "config_dir", "workspace"}:
            command = "adaf-attack paths --repair"
        blockers.append(
            {
                "id": str(check.get("id") or "doctor"),
                "message": str(check.get("detail") or check.get("id") or "blocked"),
                "remediation": remediation,
                "suggested_command": command,
            }
        )
    return blockers


def _load_engine(workspace: Path) -> WorkflowEngine | None:
    try:
        engine = WorkflowEngine(workspace, mode="interactive")
    except WorkflowError:
        return None
    if not engine.state.audit_log:
        # Mirror CLI auto-start so guidance never hits an empty dead end.
        engine.start(actor="journey")
    return engine


def _breadcrumb(
    stage: str, engine: WorkflowEngine | None, *, demo: Path | None
) -> list[dict[str, Any]]:
    order = list(STAGE_LABELS)
    idx = order.index(stage) if stage in order else 0
    steps = engine.state.completed_steps if engine is not None else []
    markers: list[dict[str, Any]] = []
    for position, key in enumerate(order):
        done = position < idx
        if key == "first-success" and demo is not None:
            done = True
        if key == "orient" and "scope-authorized" in steps:
            done = True
        if key == "discover" and "discovery-complete" in steps:
            done = True
        if (
            key == "complete"
            and engine is not None
            and engine.state.status
            in {
                "complete",
                "archived",
            }
        ):
            done = True
        markers.append(
            {
                "id": key,
                "label": STAGE_LABELS[key],
                "done": done or (key == stage and stage == "complete"),
                "current": key == stage,
            }
        )
    return markers


def _journey_action_from_workflow(
    action: WorkflowAction,
    *,
    session: Path | None,
    workspace: Path,
) -> JourneyAction:
    enriched = enrich_action(action, session=session, workspace=workspace)
    return JourneyAction(
        id=enriched["id"],
        title=enriched["title"],
        why=enriched["consequence"] or enriched["description"],
        suggested_command=enriched["suggested_command"],
        kind=enriched["kind"],
        unlock_conditions=list(enriched["unlock_conditions"]),
        advance_safe=bool(enriched["advance_safe"]),
    )


def snapshot(
    *,
    workspace: Path | None = None,
    session: Path | None = None,
    doctor: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compose the authoritative journey document for CLI/TUI/agents."""
    root = Path(workspace) if workspace is not None else default_workspace_dir()
    blockers = _doctor_blockers(doctor)
    demo = find_demo_session(root)
    session_hint = Path(session) if session is not None else find_recent_session(root)
    engine = _load_engine(root)

    tui_available = True
    try:
        import textual  # noqa: F401
    except ImportError:
        tui_available = False

    context = {
        "first_run": demo is None and (engine is None or not engine.state.findings),
        "session_hint": str(session_hint) if session_hint else None,
        "demo_available": demo is not None,
        "demo_session": str(demo) if demo else None,
        "tui_available": tui_available,
        "workspace": str(root),
    }

    primary: JourneyAction
    secondary: list[JourneyAction] = []
    stage: str

    if blockers:
        stage = "install-blocked"
        first = blockers[0]
        primary = JourneyAction(
            id="repair-install",
            title="Repair installation readiness",
            why=first["remediation"],
            suggested_command=first["suggested_command"],
            kind="required",
            unlock_conditions=["doctor profile user-readiness reports ready"],
            advance_safe=False,
        )
        secondary = [
            JourneyAction(
                id="doctor-explain",
                title="Explain doctor failures",
                why="See every blocking and advisory check before continuing.",
                suggested_command="adaf-attack doctor --profile user-readiness --explain",
                kind="recommended",
            )
        ]
    elif demo is None:
        stage = "first-success"
        primary = JourneyAction(
            id="quickstart",
            title="Run the safe offline quickstart",
            why="Creates a disposable demo session and findings dashboard without contacting AD.",
            suggested_command="adaf-attack quickstart",
            kind="required",
            unlock_conditions=["packaged demo fixtures available"],
            advance_safe=True,
        )
        secondary = [
            JourneyAction(
                id="doctor",
                title="Re-check local readiness",
                why="Confirm Python, paths, and packaged fixtures before the demo.",
                suggested_command="adaf-attack doctor --profile user-readiness --explain",
                kind="recommended",
            ),
            JourneyAction(
                id="tour",
                title="Preview the guided tour",
                why="See the full operator ladder before you begin.",
                suggested_command="adaf-attack tour",
                kind="recommended",
            ),
        ]
    elif engine is not None and engine.state.status in {"complete", "archived"}:
        stage = "complete"
        primary = JourneyAction(
            id="new-engagement",
            title="Start a new guided engagement",
            why="This workflow is finished; retain evidence or begin the next authorized assessment.",
            suggested_command="adaf-attack sessions --limit 5",
            kind="recommended",
            advance_safe=False,
        )
        secondary = [
            JourneyAction(
                id="workflow-audit",
                title="Review the audit trail",
                why="Confirm who changed what before archiving the workspace.",
                suggested_command=f"adaf-attack workflow audit --workspace {root}",
                kind="recommended",
            )
        ]
    elif engine is not None and "scope-authorized" not in engine.state.completed_steps:
        stage = "orient"
        # Prefer importing demo findings after authorize when a session exists.
        primary = JourneyAction(
            id="authorize-scope",
            title="Confirm scope and authorization",
            why="Without authorization, all network and workflow target actions remain locked.",
            suggested_command=f"adaf-attack workflow authorize --workspace {root}",
            kind="required",
            unlock_conditions=["scope and authorization decision recorded"],
            advance_safe=True,
        )
        secondary = []
        if session_hint is not None:
            secondary.append(
                JourneyAction(
                    id="import-session",
                    title="Import session findings after authorize",
                    why="Adapt saved session evidence into the guided workflow.",
                    suggested_command=(
                        f"adaf-attack workflow import-session --session {session_hint} "
                        f"--workspace {root}"
                    ),
                    kind="recommended",
                    advance_safe=True,
                )
            )
        secondary.append(
            JourneyAction(
                id="session-show",
                title="Inspect the offline demo session",
                why="Review findings before authorizing live activity.",
                suggested_command=f"adaf-attack session show --session {demo}",
                kind="recommended",
            )
        )
    elif engine is not None:
        recs = engine.recommendations(limit=5)
        # If authorized with a session but no findings ingested yet, prefer import.
        if (
            session_hint is not None
            and not engine.state.findings
            and "discovery-complete" not in engine.state.completed_steps
        ):
            stage = "discover"
            primary = JourneyAction(
                id="import-session",
                title="Import session findings into the workflow",
                why="Session evidence exists but has not been adapted into finding-driven actions.",
                suggested_command=(
                    f"adaf-attack workflow import-session --session {session_hint} "
                    f"--workspace {root}"
                ),
                kind="required",
                unlock_conditions=["authorized scope", "saved session available"],
                advance_safe=True,
            )
            if recs:
                secondary = [
                    _journey_action_from_workflow(item, session=session_hint, workspace=root)
                    for item in recs[:3]
                ]
        elif not recs:
            stage = "closeout"
            primary = JourneyAction(
                id="workflow-close",
                title="Close the guided workflow",
                why="No pending required actions remain; finish and retain the audit trail.",
                suggested_command=f"adaf-attack workflow close --workspace {root}",
                kind="required",
                advance_safe=True,
            )
            secondary = [
                JourneyAction(
                    id="cleanup-status",
                    title="Check rollback / cleanup status",
                    why="Confirm no pending directory mutations remain before closeout.",
                    suggested_command=(
                        f"adaf-attack cleanup-status --session {session_hint}"
                        if session_hint
                        else "adaf-attack sessions --limit 5"
                    ),
                    kind="recommended",
                )
            ]
        else:
            top = recs[0]
            if top.id == "generate-report" or top.phase == "reporting":
                stage = "deliver"
            elif top.phase in {"scoping"}:
                stage = "orient"
            elif top.phase == "discovery":
                stage = "discover"
            elif top.phase == "closure":
                stage = "closeout"
            else:
                stage = "operate"
            primary = _journey_action_from_workflow(top, session=session_hint, workspace=root)
            secondary = [
                _journey_action_from_workflow(item, session=session_hint, workspace=root)
                for item in recs[1:4]
            ]
            if session_hint is not None and stage == "deliver":
                secondary.insert(
                    0,
                    JourneyAction(
                        id="engagement-package",
                        title="Build a client evidence package",
                        why="Package redacted deliverables after the final report.",
                        suggested_command=(
                            f"adaf-attack engagement package --session {session_hint} "
                            f"--output engagement.zip --profile client"
                        ),
                        kind="recommended",
                    ),
                )
    else:
        stage = "first-success"
        primary = JourneyAction(
            id="quickstart",
            title="Run the safe offline quickstart",
            why="Workflow state could not be loaded; start from the offline demo.",
            suggested_command="adaf-attack quickstart",
            kind="required",
            advance_safe=True,
        )

    workflow_view: dict[str, Any] | None = None
    if engine is not None:
        guidance = engine.guidance()
        workflow_view = {
            "workflow_id": engine.state.workflow_id,
            "phase": guidance.phase,
            "status": guidance.status,
            "progress": guidance.progress,
            "risk_score": guidance.risk_score,
            "open_findings": len(engine.state.open_findings),
            "total_findings": len(engine.state.findings),
            "next_action_id": guidance.next_action_id,
            "phases": list(PHASES),
        }

    progress = STAGE_PROGRESS.get(stage, 0.0)
    if engine is not None and stage in {"operate", "deliver", "closeout", "complete"}:
        progress = max(progress, float(engine.state.progress))

    return {
        "ok": not blockers,
        "stage": stage,
        "stage_label": STAGE_LABELS.get(stage, stage),
        "progress_pct": round(progress, 1),
        "primary_action": primary.document(),
        "secondary_actions": [item.document() for item in secondary],
        "blockers": blockers,
        "workflow": workflow_view,
        "context": context,
        "breadcrumb": _breadcrumb(stage, engine, demo=demo),
        "next_step": primary.suggested_command,
    }


def import_session_findings(
    workspace: Path,
    session: Path,
    *,
    actor: str = "journey",
) -> dict[str, Any]:
    """Adapt canonical session findings into the guided workflow (local only)."""
    from adaf_attack.core.findings import findings_from_session
    from adaf_attack.core.workflow_engine import finding_from_document

    if not session.is_dir():
        raise FileNotFoundError(f"Session directory not found: {session}")
    engine = _load_engine(workspace)
    if engine is None:
        raise WorkflowError("Could not load or create workflow state")
    imported: list[str] = []
    for finding in findings_from_session(session):
        record = engine.ingest_finding(finding_from_document(finding.document()), actor=actor)
        imported.append(record.id)
    if imported and "discovery-complete" not in engine.state.completed_steps:
        # Mark discovery complete so validation actions unlock without a fake live run.
        if "scope-authorized" not in engine.state.completed_steps:
            engine.complete_action("authorize-scope", actor=actor)
        if (
            "run-discovery" in engine.state.pending_actions
            and not engine.state.pending_actions["run-discovery"].completed
        ):
            engine.complete_action("run-discovery", actor=actor)
        elif "discovery-complete" not in engine.state.completed_steps:
            engine.complete_step("discovery-complete", actor=actor, phase="validation")
    return {
        "ok": True,
        "imported": imported,
        "count": len(imported),
        "workspace": str(workspace),
        "session": str(session),
    }


__all__ = [
    "SAFE_ADVANCE_ACTIONS",
    "STAGE_LABELS",
    "JourneyAction",
    "action_is_advance_safe",
    "enrich_action",
    "find_demo_session",
    "find_recent_session",
    "import_session_findings",
    "snapshot",
    "suggested_command_for_action",
]
