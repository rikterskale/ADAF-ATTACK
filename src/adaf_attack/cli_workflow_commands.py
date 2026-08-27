"""CLI surface for the finding-driven guided workflow engine.

This module is the transport adapter that makes ``core.workflow_engine`` usable
from the command line by human operators (interactive guidance) and by
automated or agent-driven callers (``--format json``). The TUI is one client of
the same engine; this command group shares its durable ``workflow-state.json``
so a workflow started in either surface is visible and resumable in the other.

Every command loads or creates the engine, applies at most one mutation, and
emits the resulting guidance. ``WorkflowError`` from the engine is mapped to the
stable ``ActionableError`` contract so JSON and human callers get the same
codes, remediation, and next-step suggestions as the rest of the CLI.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from rich.panel import Panel
from rich.table import Table

from adaf_attack.core.cli_contract import ActionableError, error_for
from adaf_attack.core.journey import enrich_action, find_recent_session
from adaf_attack.core.paths import default_workspace_dir
from adaf_attack.core.workflow_engine import (
    WorkflowEngine,
    WorkflowError,
    finding_from_document,
)


def register_workflow_commands(
    app: typer.Typer,
    *,
    emit: Callable[..., None],
    emit_error: Callable[..., None],
    doctor_payload: Callable[..., dict[str, Any]] | None = None,
) -> None:
    """Attach the ``workflow`` command group to the main CLI app.

    ``emit`` and ``emit_error`` are the shared CLI output helpers so this group
    honors ``--format json`` and ``--no-color`` identically to every other
    command. When ``doctor_payload`` is provided, ``workflow next`` shares the
    same readiness snapshot as ``guide``.
    """

    workflow_app = typer.Typer(
        help="Finding-driven guided workflow: start to closure, interactive or agent-driven.",
    )
    app.add_typer(workflow_app, name="workflow")

    def _doctor() -> dict[str, Any] | None:
        if doctor_payload is None:
            return None
        return doctor_payload("user-readiness")

    def _resolve_workspace(workspace: Path | None) -> Path:
        return Path(workspace) if workspace is not None else default_workspace_dir()

    def _aligned_recommendations(
        journey: dict[str, Any],
        engine: WorkflowEngine,
        *,
        session: Path | None,
        workspace: Path,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Put journey primary first so recommendations[0] matches guide."""
        primary = journey.get("primary_action") or {}
        primary_cmd = str(
            journey.get("suggested_command") or primary.get("suggested_command") or ""
        )
        engine_limit = max(limit, 1)
        engine_recs = [
            enrich_action(action, session=session, workspace=workspace)
            for action in engine.recommendations(limit=engine_limit)
        ]
        aligned: list[dict[str, Any]] = []
        if primary and primary_cmd:
            aligned.append(dict(primary))
        for rec in engine_recs:
            if (
                primary
                and rec.get("id") == primary.get("id")
                and rec.get("suggested_command") == primary_cmd
            ):
                continue
            aligned.append(rec)
            if limit > 0 and len(aligned) >= limit:
                break
        if limit > 0:
            return aligned[:limit]
        return aligned

    def _engine(workspace: Path | None, *, mode: str = "interactive") -> WorkflowEngine:
        """Load or create the shared engine, auto-starting an empty workflow.

        Auto-start guarantees there are no dead ends: any command run against a
        never-initialized workspace still yields a coherent scoping-phase state
        with the mandatory ``authorize-scope`` action instead of an empty view.
        """
        root = _resolve_workspace(workspace)
        try:
            engine = WorkflowEngine(root, mode=mode)  # type: ignore[arg-type]
        except WorkflowError as exc:
            raise error_for(
                "WORKFLOW_STATE_INVALID",
                message=str(exc),
                details={"workspace": str(root)},
            ) from exc
        if not engine.state.audit_log:
            engine.start(actor=f"cli-{mode}")
        return engine

    def _guard(action: Callable[[], Any]) -> Any:
        """Run an engine mutation, mapping engine errors to the CLI contract."""
        try:
            return action()
        except WorkflowError as exc:
            raise error_for("WORKFLOW_TRANSITION_INVALID", message=str(exc)) from exc

    def _session_hint(workspace: Path | None) -> Path | None:
        root = _resolve_workspace(workspace)
        return find_recent_session(root)

    def _guidance_payload(
        engine: WorkflowEngine, *, workspace: Path | None = None
    ) -> dict[str, Any]:
        guidance = engine.guidance()
        root = _resolve_workspace(workspace)
        session = _session_hint(workspace)
        from adaf_attack.core.journey import guide_recovery_command, snapshot

        # Authoritative next step always comes from the shared journey composer.
        journey = snapshot(workspace=root, session=session, doctor=_doctor())
        primary = str(
            journey.get("suggested_command") or journey["primary_action"]["suggested_command"]
        )
        recs = _aligned_recommendations(journey, engine, session=session, workspace=root, limit=5)
        return {
            "ok": True,
            "workflow_id": engine.state.workflow_id,
            "mode": engine.state.mode,
            "guidance": guidance.document(),
            "open_findings": len(engine.state.open_findings),
            "total_findings": len(engine.state.findings),
            "recommendations": recs,
            "next_step": primary,
            "suggested_command": primary,
            "recovery_command": guide_recovery_command(workspace=root, session=session),
            "journey_stage": journey.get("stage"),
            "primary_action": journey.get("primary_action"),
        }

    def _guidance_panel(
        engine: WorkflowEngine, *, title: str, workspace: Path | None = None
    ) -> Panel:
        g = engine.guidance()
        root = _resolve_workspace(workspace)
        session = _session_hint(workspace)
        from adaf_attack.core.journey import guide_recovery_command, snapshot

        journey = snapshot(workspace=root, session=session, doctor=_doctor())
        primary = str(
            journey.get("suggested_command") or journey["primary_action"]["suggested_command"]
        )
        recs = _aligned_recommendations(journey, engine, session=session, workspace=root, limit=3)
        lines = [
            f"Phase:    {g.phase}",
            f"Status:   {g.status}",
            f"Progress: {g.progress:.1f}%    Risk: {g.risk_score:.1f}",
            f"Open findings: {len(engine.state.open_findings)} of {len(engine.state.findings)}",
            f"Journey:  {journey.get('stage_label')} ({journey.get('stage')})",
            "",
            f"Next step: {g.explanation}",
            f"Copy-ready: {primary}",
        ]
        if recs:
            lines.append("")
            lines.append("Recommended next actions:")
            for action in recs:
                marker = (
                    "!"
                    if action["kind"] == "required"
                    else ("?" if action["kind"] == "decision" else "-")
                )
                lines.append(f"  [{marker}] {action['id']}  ({action['kind']})")
                lines.append(f"        {action['title']}")
                lines.append(f"        {action['suggested_command']}")
        elif engine.state.status in {"complete", "archived"}:
            lines.append("")
            lines.append(f"Workflow {engine.state.status}; retained for review.")
        else:
            lines.append("")
            lines.append("No pending actions. Run `workflow close` to finish.")
        lines.append("")
        lines.append(f"When lost: {guide_recovery_command(workspace=root, session=session)}")
        return Panel("\n".join(lines), title=title)

    def _emit_guidance(
        ctx: typer.Context, engine: WorkflowEngine, *, title: str, workspace: Path | None = None
    ) -> None:
        emit(
            ctx,
            _guidance_payload(engine, workspace=workspace),
            _guidance_panel(engine, title=title, workspace=workspace),
        )

    # --- read / guidance -----------------------------------------------------

    @workflow_app.command("status")
    def workflow_status(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(
            None, "--workspace", help="Workflow workspace (defaults to the shared TUI workspace)."
        ),
    ) -> None:
        """Show the current phase, progress, risk, and next-step guidance."""
        try:
            engine = _engine(workspace)
        except ActionableError as error:
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from error
        _emit_guidance(ctx, engine, title="Guided workflow status", workspace=workspace)

    @workflow_app.command("next")
    def workflow_next(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(None, "--workspace"),
        session: Path | None = typer.Option(
            None,
            "--session",
            help="Bias discover/deliver stages toward this session (matches guide).",
        ),
        limit: int = typer.Option(5, "--limit", help="Maximum recommendations to return."),
    ) -> None:
        """List ranked actions; authoritative next step matches ``guide``."""
        try:
            engine = _engine(workspace)
        except ActionableError as error:
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from error
        root = _resolve_workspace(workspace)
        session_hint = Path(session) if session is not None else _session_hint(workspace)
        from adaf_attack.core.journey import guide_recovery_command, snapshot

        journey = snapshot(workspace=root, session=session_hint, doctor=_doctor())
        primary = str(
            journey.get("suggested_command") or journey["primary_action"]["suggested_command"]
        )
        recs = _aligned_recommendations(
            journey,
            engine,
            session=session_hint,
            workspace=root,
            limit=max(0, limit),
        )
        payload = {
            "ok": True,
            "count": len(recs),
            "recommendations": recs,
            "next_step": primary,
            "suggested_command": primary,
            "recovery_command": guide_recovery_command(workspace=root, session=session_hint),
            "journey_stage": journey.get("stage"),
            "primary_action": journey.get("primary_action"),
        }
        table = Table(title="Ranked next actions")
        table.add_column("Action")
        table.add_column("Kind")
        table.add_column("Copy-ready command")
        for a in recs:
            kind = "journey" if a.get("suggested_command") == primary else a.get("kind", "-")
            table.add_row(str(a.get("id")), str(kind), str(a.get("suggested_command")))
        if not recs and journey.get("stage") not in {"first-success", "install-blocked"}:
            table.add_row("(none)", "-", "No engine action pending; follow the journey command.")
        emit(ctx, payload, table)

    @workflow_app.command("snapshot")
    def workflow_snapshot(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(None, "--workspace"),
    ) -> None:
        """Emit the full state plus guidance and recommendations (agent context)."""
        try:
            engine = _engine(workspace, mode="agent")
        except ActionableError as error:
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from error
        document = engine.snapshot()
        document["ok"] = True
        emit(
            ctx,
            document,
            _guidance_panel(engine, title="Workflow snapshot", workspace=workspace),
        )

    @workflow_app.command("findings")
    def workflow_findings(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(None, "--workspace"),
        status: str | None = typer.Option(None, "--status", help="open/validated/…/closed."),
        severity: str | None = typer.Option(None, "--severity"),
        source: str | None = typer.Option(None, "--source"),
        tag: str | None = typer.Option(None, "--tag"),
        asset: str | None = typer.Option(None, "--asset"),
    ) -> None:
        """Query findings by status, severity, source, tag, or affected asset."""
        try:
            engine = _engine(workspace)
            records = _guard(
                lambda: engine.query_findings(
                    status=status,  # type: ignore[arg-type]
                    severity=severity,
                    source=source,
                    tag=tag,
                    asset=asset,
                )
            )
        except ActionableError as error:
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from error
        payload = {
            "ok": True,
            "count": len(records),
            "findings": [
                {
                    "id": r.id,
                    "title": r.title,
                    "severity": r.severity,
                    "confidence": r.confidence,
                    "status": r.status,
                    "priority": r.priority,
                    "affected_assets": r.affected_assets,
                    "source": r.source,
                    "tags": r.tags,
                    "related_findings": r.related_findings,
                }
                for r in records
            ],
        }
        table = Table(title="Findings")
        table.add_column("ID")
        table.add_column("Severity")
        table.add_column("Status")
        table.add_column("Priority", justify="right")
        table.add_column("Title")
        for r in records:
            table.add_row(r.id, r.severity, r.status, f"{r.priority:.0f}", r.title)
        emit(ctx, payload, table)

    @workflow_app.command("actions")
    def workflow_actions(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(None, "--workspace"),
        phase: str | None = typer.Option(None, "--phase"),
        kind: str | None = typer.Option(None, "--kind", help="required/recommended/decision."),
        include_completed: bool = typer.Option(False, "--all", help="Include completed actions."),
    ) -> None:
        """List pending (or all) derived actions for a phase or kind."""
        try:
            engine = _engine(workspace)
            actions = _guard(
                lambda: engine.query_actions(
                    phase=phase, kind=kind, include_completed=include_completed
                )
            )
        except ActionableError as error:
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from error
        payload = {
            "ok": True,
            "count": len(actions),
            "actions": [
                {
                    "id": a.id,
                    "kind": a.kind,
                    "phase": a.phase,
                    "title": a.title,
                    "completed": a.completed,
                    "consequence": a.consequence,
                    "finding_ids": a.finding_ids,
                }
                for a in actions
            ],
        }
        table = Table(title="Workflow actions")
        table.add_column("ID")
        table.add_column("Kind")
        table.add_column("Phase")
        table.add_column("Done")
        for a in actions:
            table.add_row(a.id, a.kind, a.phase, "yes" if a.completed else "no")
        emit(ctx, payload, table)

    @workflow_app.command("audit")
    def workflow_audit(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(None, "--workspace"),
        event_type: str | None = typer.Option(None, "--type", help="Filter by audit event type."),
    ) -> None:
        """Show the append-only audit history (who changed what, when, and why)."""
        try:
            engine = _engine(workspace)
            events = engine.audit_history(event_type=event_type)
        except ActionableError as error:
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from error
        payload = {
            "ok": True,
            "count": len(events),
            "events": [
                {
                    "event_id": e.event_id,
                    "event_type": e.event_type,
                    "timestamp": e.timestamp,
                    "actor": e.actor,
                    "summary": e.summary,
                }
                for e in events
            ],
        }
        table = Table(title="Audit history")
        table.add_column("When")
        table.add_column("Actor")
        table.add_column("Event")
        table.add_column("Summary")
        for e in events:
            table.add_row(e.timestamp, e.actor, e.event_type, e.summary)
        emit(ctx, payload, table)

    # --- mutations -----------------------------------------------------------

    @workflow_app.command("authorize")
    def workflow_authorize(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(None, "--workspace"),
        actor: str = typer.Option("operator", "--actor"),
    ) -> None:
        """Record the scope/authorization decision that unlocks target activity."""
        try:
            engine = _engine(workspace)
            _guard(lambda: engine.complete_action("authorize-scope", actor=actor))
        except ActionableError as error:
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from error
        _emit_guidance(ctx, engine, title="Scope authorized", workspace=workspace)

    @workflow_app.command("inject")
    def workflow_inject(
        ctx: typer.Context,
        title: str = typer.Argument(..., help="Finding title."),
        workspace: Path | None = typer.Option(None, "--workspace"),
        finding_id: str | None = typer.Option(None, "--id", help="Stable finding ID."),
        severity: str = typer.Option("info", "--severity"),
        confidence: str = typer.Option("unknown", "--confidence"),
        impact: str = typer.Option("", "--impact"),
        remediation: str = typer.Option("", "--remediation"),
        asset: list[str] = typer.Option([], "--asset", help="Affected asset; repeatable."),
        tag: list[str] = typer.Option([], "--tag", help="Finding tag; repeatable."),
        actor: str = typer.Option("operator", "--actor"),
    ) -> None:
        """Inject an operator finding into the workflow, driving new branches."""
        try:
            engine = _engine(workspace)
            fields: dict[str, Any] = {
                "severity": severity,
                "confidence": confidence,
                "impact": impact,
                "remediation": remediation,
                "affected_assets": list(asset),
                "tags": list(tag),
            }
            if finding_id:
                fields["id"] = finding_id
            record = _guard(lambda: engine.inject_finding(title, actor=actor, **fields))
        except ActionableError as error:
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from error
        payload = _guidance_payload(engine, workspace=workspace)
        payload["finding"] = {"id": record.id, "priority": record.priority}
        emit(
            ctx,
            payload,
            _guidance_panel(engine, title=f"Finding injected: {record.id}", workspace=workspace),
        )

    @workflow_app.command("import-session")
    def workflow_import_session(
        ctx: typer.Context,
        session: Path = typer.Option(..., "--session", help="Saved session directory."),
        workspace: Path | None = typer.Option(None, "--workspace"),
        actor: str = typer.Option("session", "--actor"),
    ) -> None:
        """Adapt canonical session findings into the guided workflow."""
        from adaf_attack.core.findings import findings_from_session

        try:
            if not session.is_dir():
                raise error_for("SESSION_NOT_FOUND", details={"session": str(session)})
            engine = _engine(workspace)
            imported: list[str] = []
            try:
                for finding in findings_from_session(session):
                    record = engine.ingest_finding(
                        finding_from_document(finding.document()), actor=actor
                    )
                    imported.append(record.id)
            except WorkflowError as exc:
                raise error_for("WORKFLOW_TRANSITION_INVALID", message=str(exc)) from exc
        except ActionableError as error:
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from error
        payload = _guidance_payload(engine, workspace=workspace)
        payload["imported"] = imported
        payload["imported_count"] = len(imported)
        emit(
            ctx,
            payload,
            _guidance_panel(
                engine, title=f"Imported {len(imported)} session finding(s)", workspace=workspace
            ),
        )

    @workflow_app.command("enrich")
    def workflow_enrich(
        ctx: typer.Context,
        finding_id: str = typer.Argument(..., help="Finding ID to enrich."),
        workspace: Path | None = typer.Option(None, "--workspace"),
        severity: str | None = typer.Option(None, "--severity"),
        confidence: str | None = typer.Option(None, "--confidence"),
        impact: str | None = typer.Option(None, "--impact"),
        remediation: str | None = typer.Option(None, "--remediation"),
        asset: list[str] = typer.Option([], "--asset", help="Replace affected assets; repeatable."),
        actor: str = typer.Option("operator", "--actor"),
    ) -> None:
        """Enrich a finding's severity, confidence, impact, or affected assets."""
        updates: dict[str, Any] = {}
        if severity is not None:
            updates["severity"] = severity
        if confidence is not None:
            updates["confidence"] = confidence
        if impact is not None:
            updates["impact"] = impact
        if remediation is not None:
            updates["remediation"] = remediation
        if asset:
            updates["affected_assets"] = list(asset)
        try:
            if not updates:
                raise error_for(
                    "REQUIRED_INPUT_MISSING",
                    message="Provide at least one field to enrich.",
                )
            engine = _engine(workspace)
            _guard(lambda: engine.enrich_finding(finding_id, actor=actor, **updates))
        except ActionableError as error:
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from error
        _emit_guidance(ctx, engine, title=f"Finding enriched: {finding_id}", workspace=workspace)

    @workflow_app.command("correlate")
    def workflow_correlate(
        ctx: typer.Context,
        finding_id: list[str] = typer.Argument(..., help="Two or more finding IDs to correlate."),
        workspace: Path | None = typer.Option(None, "--workspace"),
        relation: str = typer.Option("related", "--relation"),
        actor: str = typer.Option("operator", "--actor"),
    ) -> None:
        """Link findings so their relationship informs prioritization and reporting."""
        try:
            if len(finding_id) < 2:
                raise error_for(
                    "REQUIRED_INPUT_MISSING",
                    message="Correlation needs at least two finding IDs.",
                )
            engine = _engine(workspace)
            _guard(lambda: engine.correlate(finding_id, actor=actor, relation=relation))
        except ActionableError as error:
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from error
        _emit_guidance(ctx, engine, title="Findings correlated", workspace=workspace)

    @workflow_app.command("transition")
    def workflow_transition(
        ctx: typer.Context,
        finding_id: str = typer.Argument(..., help="Finding ID."),
        status: str = typer.Argument(..., help="open/validated/exploited/mitigated/closed."),
        workspace: Path | None = typer.Option(None, "--workspace"),
        note: str | None = typer.Option(
            None, "--note", help="Evidence note attached to the change."
        ),
        artifact: str | None = typer.Option(
            None, "--artifact", help="Relative evidence artifact path for closure/verification."
        ),
        pointer: str = typer.Option("/", "--pointer", help="JSON pointer within --artifact."),
        sha256: str | None = typer.Option(
            None, "--sha256", help="SHA-256 of the evidence artifact."
        ),
        actor: str = typer.Option("operator", "--actor"),
    ) -> None:
        """Advance a finding's lifecycle status (monotonic, evidence-gated)."""
        try:
            engine = _engine(workspace)
            evidence = None
            if artifact:
                evidence = {"artifact": artifact, "pointer": pointer}
                if sha256:
                    evidence["sha256"] = sha256
                if note:
                    evidence["note"] = note
            elif note:
                if status == "closed":
                    # Preserve the convenient --note workflow while making
                    # closure evidence durable and independently inspectable.
                    artifact_name = f"verification-{finding_id}.json"
                    artifact_path = engine.workspace / artifact_name
                    artifact_path.write_text(
                        json.dumps(
                            {
                                "finding_id": finding_id,
                                "note": note,
                                "actor": actor,
                            },
                            indent=2,
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    evidence = {"artifact": artifact_name, "pointer": "/note"}
                else:
                    evidence = {"type": "operator-note", "value": note}
            _guard(
                lambda: engine.transition_finding(
                    finding_id,
                    status,  # type: ignore[arg-type]  # validated by the engine
                    actor=actor,
                    evidence=evidence,
                )
            )
        except ActionableError as error:
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from error
        _emit_guidance(ctx, engine, title=f"{finding_id} -> {status}", workspace=workspace)

    @workflow_app.command("decide")
    def workflow_decide(
        ctx: typer.Context,
        action_id: str = typer.Argument(..., help="Decision action ID (e.g. decision:ADAF-1)."),
        decision: str = typer.Argument(..., help="e.g. mitigate, accept-risk, confirm-impact."),
        workspace: Path | None = typer.Option(None, "--workspace"),
        rationale: str = typer.Option("", "--rationale"),
        actor: str = typer.Option("operator", "--actor"),
    ) -> None:
        """Record a response decision at a decision point."""
        try:
            engine = _engine(workspace)
            _guard(lambda: engine.decide(action_id, decision, actor=actor, rationale=rationale))
        except ActionableError as error:
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from error
        _emit_guidance(ctx, engine, title="Decision recorded", workspace=workspace)

    @workflow_app.command("do")
    def workflow_do(
        ctx: typer.Context,
        action_id: str = typer.Argument(..., help="Action ID from `workflow next`."),
        workspace: Path | None = typer.Option(None, "--workspace"),
        actor: str = typer.Option("operator", "--actor"),
    ) -> None:
        """Complete a required or recommended action, advancing the workflow."""
        try:
            engine = _engine(workspace)
            action = engine.state.pending_actions.get(action_id)
            if action is not None and action.kind == "decision":
                raise error_for(
                    "WORKFLOW_TRANSITION_INVALID",
                    message=f"{action_id} is a decision point; use `workflow decide`.",
                )
            _guard(lambda: engine.complete_action(action_id, actor=actor))
        except ActionableError as error:
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from error
        _emit_guidance(ctx, engine, title=f"Action completed: {action_id}", workspace=workspace)

    @workflow_app.command("close")
    def workflow_close(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(None, "--workspace"),
        archive: bool = typer.Option(False, "--archive", help="Archive instead of complete."),
        actor: str = typer.Option("operator", "--actor"),
    ) -> None:
        """Finish the workflow: generate final report and close or archive."""
        try:
            engine = _engine(workspace)
            _guard(lambda: engine.close(actor=actor, archive=archive))
        except ActionableError as error:
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from error
        payload = _guidance_payload(engine, workspace=workspace)
        payload["final_status"] = engine.state.status
        emit(
            ctx,
            payload,
            _guidance_panel(engine, title=f"Workflow {engine.state.status}", workspace=workspace),
        )


__all__ = ["register_workflow_commands"]
