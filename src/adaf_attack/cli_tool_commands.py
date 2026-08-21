"""Unified operator-tool command group for offline evidence workflows."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from rich.panel import Panel

from adaf_attack.core.cli_contract import ActionableError


def register_tool_commands(
    app: typer.Typer,
    *,
    emit: Callable[..., None],
    emit_error: Callable[..., None],
) -> None:
    """Register tool-oriented aliases without changing execution safeguards."""
    tool_app = typer.Typer(help="Offline graph, evidence, scope, detection, and lab tools.")
    app.add_typer(tool_app, name="tool")

    @tool_app.command("graph")
    def tool_graph(
        ctx: typer.Context,
        graph: Path = typer.Argument(..., help="Saved graph.json file."),
        start: str | None = typer.Option(None, "--start", "-s"),
        limit: int = typer.Option(25, "--limit"),
    ) -> None:
        """Explore a saved graph and rank evidence-backed paths offline."""
        from adaf_attack.core.tooling import graph_explorer

        try:
            if not graph.is_file():
                raise FileNotFoundError(str(graph))
            payload = graph_explorer(graph, start=start, limit=limit)
        except (OSError, ValueError, KeyError) as exc:
            error = ActionableError("GRAPH_NOT_FOUND", str(exc), "Pass a valid saved graph.json file.")
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        emit(ctx, {"ok": True, **payload}, Panel(
            f"Nodes: {payload['summary'].get('nodes', 0)}\n"
            f"Edges: {payload['summary'].get('edges', 0)}\n"
            f"Ranked paths: {payload['path_count']}\nOffline: yes",
            title="Graph explorer",
        ))

    @tool_app.command("evidence-import")
    def tool_evidence_import(
        ctx: typer.Context,
        session: Path = typer.Option(..., "--session"),
        source: Path = typer.Option(..., "--source"),
        overwrite: bool = typer.Option(False, "--overwrite"),
    ) -> None:
        """Import a validated JSON artifact into a session without contacting a target."""
        from adaf_attack.core.tooling import import_evidence

        try:
            payload = import_evidence(session, source, overwrite=overwrite)
        except (OSError, ValueError) as exc:
            error = ActionableError("INPUT_FILE_INVALID", str(exc), "Check the session, source path, and JSON format.")
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        emit(ctx, payload, Panel(f"Imported: {source.name}\nDestination: {payload['destination']}", title="Evidence import"))

    @tool_app.command("scope")
    def tool_scope(ctx: typer.Context, plan: Path = typer.Argument(..., help="YAML scope or engagement plan.")) -> None:
        """Inspect authorized scope, capabilities, and OPSEC settings without execution."""
        from adaf_attack.core.tooling import scope_summary

        try:
            payload = scope_summary(plan)
        except (OSError, ValueError) as exc:
            error = ActionableError("ENGAGEMENT_PLAN_INVALID", str(exc), "Correct the YAML scope document and retry.")
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        emit(ctx, {"ok": True, **payload}, Panel(
            f"Engagement: {payload.get('engagement_id') or '-'}\n"
            f"Target: {payload['target']}\nCapabilities: {len(payload['allowed_capabilities'])}\n"
            f"Allowed targets: {len(payload['allowed_targets'])}\nOPSEC: {payload['opsec_profile']}\n"
            "Execution: inspection-only",
            title="Scope manager",
        ))

    @tool_app.command("verify")
    def tool_verify(
        ctx: typer.Context,
        session: Path = typer.Option(..., "--session"),
        finding_id: str = typer.Option(..., "--id"),
        evidence: list[str] = typer.Option([], "--evidence", help="Evidence reference; repeat as needed."),
    ) -> None:
        """Verify remediation evidence and close one finding."""
        from adaf_attack.core.tooling import verify_finding

        try:
            payload = verify_finding(session, finding_id, evidence=evidence)
        except (OSError, ValueError, KeyError) as exc:
            error = ActionableError("UNKNOWN_FINDING", str(exc), "Pass a writable session and a valid finding ID.")
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        emit(ctx, payload, Panel(
            f"Finding: {finding_id}\nStatus: remediated\nVerification evidence: {len(evidence)}",
            title="Remediation verification",
        ))

    @tool_app.command("detect")
    def tool_detect(ctx: typer.Context, session: Path = typer.Option(..., "--session"), output: Path | None = typer.Option(None, "--output")) -> None:
        """Export evidence-backed detection hypotheses for defender review."""
        from adaf_attack.core.tooling import detection_export

        try:
            payload = detection_export(session)
            if output:
                output.parent.mkdir(parents=True, exist_ok=True)
                import json

                output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
                payload["output"] = str(output)
        except (OSError, ValueError) as exc:
            error = ActionableError("INPUT_FILE_INVALID", str(exc), "Pass a completed session directory.")
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        emit(ctx, payload, Panel(f"Detection hypotheses: {payload['count']}\nStatus: review required", title="Detection export"))

    @tool_app.command("lab")
    def tool_lab(ctx: typer.Context, manifest: Path = typer.Argument(..., help="Disposable lab manifest JSON.")) -> None:
        """Inspect a disposable lab manifest without network access."""
        from adaf_attack.core.tooling import lab_manifest_summary

        try:
            payload = lab_manifest_summary(manifest)
        except (OSError, ValueError) as exc:
            error = ActionableError("INPUT_FILE_INVALID", str(exc), "Pass a valid disposable lab manifest JSON file.")
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        emit(ctx, {"ok": True, **payload}, Panel(
            f"Domain: {payload['domain']}\nReserved domain: {'yes' if payload['reserved_domain'] else 'no'}\n"
            f"Snapshot: {payload.get('snapshot') or '-'}\nFixtures: {len(payload['fixtures'])}\n"
            f"Ready for review: {'yes' if payload['ready_for_review'] else 'no'}",
            title="Disposable lab manager",
        ))

    @app.command("credential-inventory")
    def credential_inventory(ctx: typer.Context, session: list[Path] = typer.Option(..., "--session")) -> None:
        """Inventory credential-exposure artifacts without revealing secret values."""
        from adaf_attack.core.workflows import credential_exposure

        missing = [str(path) for path in session if not path.is_dir()]
        if missing:
            error = ActionableError("SESSION_NOT_FOUND", "One or more sessions do not exist.", "Pass completed session directories.", details={"missing": missing})
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        payload = credential_exposure(session)
        emit(ctx, {"ok": True, **payload}, Panel(f"Exposure artifacts: {payload['count']}\nSecret values: redacted", title="Credential inventory"))

    @app.command("cockpit")
    def cockpit(
        ctx: typer.Context,
        session: Path = typer.Option(..., "--session"),
        start: str | None = typer.Option(None, "--start"),
    ) -> None:
        """Open an evidence-first cockpit for a completed session."""
        from adaf_attack.core.standout_ux import evidence_cockpit

        try:
            payload = evidence_cockpit(session, start=start)
        except (OSError, ValueError, KeyError) as exc:
            error = ActionableError("SESSION_NOT_FOUND", str(exc), "Pass a completed session directory.")
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        graph = payload.get("graph") or {}
        emit(ctx, payload, Panel(
            f"Findings: {payload['dashboard'].get('finding_count', 0)}\n"
            f"Graph paths: {graph.get('path_count', 0)}\n"
            f"Priority focus: {len(payload['priority_focus'])}\n"
            "Evidence-derived and offline",
            title="Evidence cockpit",
        ))

    @app.command("what-if")
    def what_if(
        ctx: typer.Context,
        graph: Path = typer.Option(..., "--graph"),
        remove_relation: str | None = typer.Option(None, "--remove-relation"),
        remove_source: str | None = typer.Option(None, "--remove-source"),
        remove_target: str | None = typer.Option(None, "--remove-target"),
    ) -> None:
        """Simulate graph changes offline without modifying evidence or targets."""
        from adaf_attack.core.standout_ux import what_if_graph

        try:
            payload = what_if_graph(graph, remove_relation=remove_relation, remove_source=remove_source, remove_target=remove_target)
        except (OSError, ValueError, KeyError) as exc:
            error = ActionableError("GRAPH_NOT_FOUND", str(exc), "Pass a valid graph.json and simulation filter.")
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        emit(ctx, payload, Panel(
            f"Removed edges: {len(payload['removed_edges'])}\n"
            f"Paths: {payload['paths_before']} → {payload['paths_after']}\n"
            "No target or source evidence was changed.",
            title="Offline what-if simulation",
        ))

    @app.command("timeline")
    def timeline(ctx: typer.Context, session: Path = typer.Option(..., "--session"), limit: int = typer.Option(100, "--limit")) -> None:
        """Show a replayable audit timeline for a session."""
        from adaf_attack.core.standout_ux import session_timeline

        try:
            payload = session_timeline(session, limit=limit)
        except OSError as exc:
            error = ActionableError("SESSION_NOT_FOUND", str(exc), "Pass a completed session directory.")
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        lines = [f"{item.get('time') or '-'}  {item['type']}  {item.get('capability') or ''}" for item in payload["events"][-10:]]
        emit(ctx, payload, Panel("\n".join(lines) or "No audit events found.", title="Engagement timeline"))

    @app.command("copilot")
    def copilot(ctx: typer.Context, session: Path = typer.Option(..., "--session")) -> None:
        """Recommend the next evidence-backed action without executing it."""
        from adaf_attack.core.standout_ux import copilot_recommendations

        try:
            payload = copilot_recommendations(session)
        except (OSError, ValueError) as exc:
            error = ActionableError("SESSION_NOT_FOUND", str(exc), "Pass a completed session directory.")
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        emit(ctx, payload, Panel(
            "\n".join(f"{i + 1}. {item['action']} — {item['why']}\n   {item['command']}" for i, item in enumerate(payload["recommendations"])),
            title="Evidence copilot — suggestions only",
        ))

    @app.command("collaboration")
    def collaboration(ctx: typer.Context, session: Path = typer.Option(..., "--session")) -> None:
        """Show finding ownership and collaboration state for a session."""
        from adaf_attack.core.standout_ux import collaboration_summary

        try:
            payload = collaboration_summary(session)
        except (OSError, ValueError) as exc:
            error = ActionableError("SESSION_NOT_FOUND", str(exc), "Pass a completed session directory.")
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        emit(ctx, payload, Panel(
            f"Owners: {', '.join(payload['owners']) or 'unassigned'}\nCommented findings: {payload['commented_findings']}",
            title="Collaborative findings workspace",
        ))
