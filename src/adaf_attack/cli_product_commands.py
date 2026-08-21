"""Product-level command views: command center, story, replay, confidence, and deliverables."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from rich.panel import Panel

from adaf_attack.core.cli_contract import ActionableError


def register_product_commands(app: typer.Typer, *, emit: Callable[..., None], emit_error: Callable[..., None]) -> None:
    """Register product surfaces while leaving collaboration/profile features untouched."""

    def _run(ctx: typer.Context, name: str, session: Path, factory: Callable[[Path], dict[str, Any]], human: Callable[[dict[str, Any]], str]) -> None:
        try:
            if not session.is_dir():
                raise FileNotFoundError(str(session))
            payload = factory(session)
        except (OSError, ValueError, KeyError) as exc:
            error = ActionableError("SESSION_NOT_FOUND", str(exc), "Pass a completed session directory.")
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        emit(ctx, payload, Panel(human(payload), title=name))

    @app.command("command-center")
    def command_center(ctx: typer.Context, session: Path = typer.Option(..., "--session")) -> None:
        """Open the polished mission-control view for an engagement."""
        from adaf_attack.core.product import command_center as build

        _run(ctx, "ADAF Command Center", session, build, lambda p: f"{p['headline']}\nMode: {p['mode']}\nTimeline events: {p['timeline']['count']}\nReports ready: {'yes' if p['deliverables']['ready'] else 'not yet'}")

    @app.command("impact-map")
    def impact_map(ctx: typer.Context, session: Path = typer.Option(..., "--session")) -> None:
        """Map evidence to findings, assets, paths, and business impact."""
        from adaf_attack.core.product import evidence_impact_map

        _run(ctx, "Evidence-to-impact map", session, evidence_impact_map, lambda p: f"Mapped findings: {p['count']}\nOffline evidence correlation complete.")

    @app.command("investigate")
    def investigate(ctx: typer.Context, session: Path = typer.Option(..., "--session")) -> None:
        """Enter zero-noise read-only investigation mode over saved evidence."""
        from adaf_attack.core.product import zero_noise_investigation

        _run(ctx, "Zero-noise investigation", session, zero_noise_investigation, lambda p: f"Artifacts: {len(p['artifacts'])}\nFindings: {p['finding_count']}\nNetwork contact: no\nTarget mutation: no")

    @app.command("story")
    def story(ctx: typer.Context, session: Path = typer.Option(..., "--session")) -> None:
        """Build an executive story from technical findings."""
        from adaf_attack.core.product import executive_story

        _run(ctx, "Executive story", session, executive_story, lambda p: p["narrative"])

    @app.command("replay")
    def replay(ctx: typer.Context, session: Path = typer.Option(..., "--session"), limit: int = typer.Option(100, "--limit")) -> None:
        """Replay a session timeline for review and handoff."""
        from adaf_attack.core.standout_ux import session_timeline

        def human(payload: dict[str, Any]) -> str:
            events = payload.get("events")
            if not isinstance(events, list):
                return "No events recorded."
            return "\n".join(
                f"{event.get('time') or '-'}  {event.get('type', '-') }  {event.get('capability') or ''}"
                for event in events[-12:]
                if isinstance(event, dict)
            ) or "No events recorded."

        _run(ctx, "Engagement replay", session, session_timeline, human)

    @app.command("confidence")
    def confidence(ctx: typer.Context, session: Path = typer.Option(..., "--session")) -> None:
        """Show confidence quality and findings needing more evidence."""
        from adaf_attack.core.product import confidence_report

        _run(ctx, "Confidence report", session, confidence_report, lambda p: f"Quality: {p['quality']}\nCounts: {p['confidence_counts']}\nNeeds more evidence: {', '.join(p['needs_more_evidence']) or 'none'}")

    @app.command("product-templates")
    def templates(ctx: typer.Context) -> None:
        """List polished repeatable assessment templates."""
        from adaf_attack.core.product import product_templates

        templates = product_templates()
        payload = {"ok": True, "templates": templates}
        emit(ctx, payload, Panel("\n".join(f"{item['id']}: {item['description']}" for item in templates), title="Assessment templates"))

    @app.command("deliverables")
    def deliverables(ctx: typer.Context, session: Path = typer.Option(..., "--session")) -> None:
        """Show the one-click client deliverables manifest."""
        from adaf_attack.core.product import deliverables_manifest

        _run(ctx, "Client deliverables", session, deliverables_manifest, lambda p: f"Ready: {'yes' if p['ready'] else 'not yet'}\nAvailable: {', '.join(p['available']) or 'none'}\nGenerate: {p['generate_command']}")
