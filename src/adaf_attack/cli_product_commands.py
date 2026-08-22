"""Product-level command views: command center, story, replay, confidence, and deliverables."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from rich.panel import Panel

from adaf_attack.core.cli_contract import ActionableError


def register_product_commands(
    app: typer.Typer,
    *,
    emit: Callable[..., None],
    emit_error: Callable[..., None],
    engagement_group: typer.Typer | None = None,
) -> None:
    """Register product surfaces while leaving collaboration/profile features untouched."""

    def _run(
        ctx: typer.Context,
        name: str,
        session: Path,
        factory: Callable[[Path], dict[str, Any]],
        human: Callable[[dict[str, Any]], str],
    ) -> None:
        try:
            if not session.is_dir():
                raise FileNotFoundError(str(session))
            payload = factory(session)
        except (OSError, ValueError, KeyError) as exc:
            error = ActionableError(
                "SESSION_NOT_FOUND", str(exc), "Pass a completed session directory."
            )
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        emit(ctx, payload, Panel(human(payload), title=name))

    engagement_app = engagement_group
    if engagement_app is None:
        engagement_app = typer.Typer(help="Goal-first engagement views and mission workflows.")
        app.add_typer(engagement_app, name="engagement")

    @engagement_app.command("dashboard")
    def engagement_dashboard_cmd(
        ctx: typer.Context,
        session: Path = typer.Option(..., "--session"),
        objective: str | None = typer.Option(None, "--objective"),
        mode: str = typer.Option("OBSERVE", "--mode", help="OBSERVE, VALIDATE, or EMULATE."),
        ranking: str = typer.Option(
            "balanced",
            "--rank-by",
            help="balanced, fastest, quietest, safest, least-disruptive, or purple-team.",
        ),
    ) -> None:
        """Show the unified scope, access, findings, paths, and next-actions view."""
        from adaf_attack.core.engagement_dashboard import dashboard as engagement_dashboard

        def human(payload: dict[str, Any]) -> str:
            engagement = payload["engagement"]
            health = payload["health"]
            objective_data = payload["objective"]
            actions = payload["recommended_next_actions"]
            return (
                f"Engagement: {engagement['id']}  Mode: {engagement['mode']}\n"
                f"Objective: {objective_data['title']} ({objective_data['progress']}% complete)\n"
                f"Scope: {health['scope']}  Evidence: {health['evidence']}  Reports: {'ready' if health['report_ready'] else 'blocked'}\n"
                f"Findings: {payload['findings']['count']}  Attack paths: {payload['attack_paths']['edges']} edges\n\n"
                f"Ranking: {payload['ranking']}\n"
                f"Breadcrumb: {payload['breadcrumbs']['engagement']} / {payload['breadcrumbs']['objective']} / "
                f"{payload['breadcrumbs']['finding'] or '-'} / {payload['breadcrumbs']['current_action'] or '-'}\n"
                "Recommended next actions:\n"
                + "\n".join(
                    f"{i}. {item['action']} [{item['risk']}] — {item['why']}"
                    for i, item in enumerate(actions[:5], 1)
                )
            )

        _run(
            ctx,
            "Engagement dashboard",
            session,
            lambda p: engagement_dashboard(p, objective=objective, mode=mode, ranking=ranking),
            human,
        )

    @engagement_app.command("missions")
    def engagement_missions(ctx: typer.Context) -> None:
        """List goal-first guided mission workflows."""
        from adaf_attack.core.engagement_dashboard import missions as mission_workflows

        missions = mission_workflows()
        emit(
            ctx,
            {"ok": True, "missions": missions, "count": len(missions)},
            Panel(
                "\n".join(
                    f"{item['id']}: {item['title']}\n  Goal-first workflow" for item in missions
                ),
                title="Guided missions",
            ),
        )

    @engagement_app.command("mission")
    def engagement_mission(ctx: typer.Context, mission_id: str = typer.Argument(...)) -> None:
        """Show the deterministic capability sequence for one mission."""
        from adaf_attack.core.engagement_dashboard import mission as find_mission

        mission = find_mission(mission_id)
        if mission is None:
            error = ActionableError(
                "UNKNOWN_MISSION",
                f"Unknown mission: {mission_id}",
                "Run `adaf-attack engagement missions` to list available missions.",
            )
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        emit(
            ctx,
            {"ok": True, "mission": mission},
            Panel(
                f"{mission['title']}\n\n{mission['objective']}\n\nSequence:\n"
                + "\n".join(f"{i}. {item}" for i, item in enumerate(mission["capabilities"], 1)),
                title="Mission workflow",
            ),
        )

    @engagement_app.command("mission-saved")
    def engagement_saved_missions(ctx: typer.Context) -> None:
        """List locally saved goal-first mission templates."""
        from adaf_attack.core.engagement_dashboard import mission as find_mission
        from adaf_attack.core.user_config import saved_missions

        ids = saved_missions()
        values = [find_mission(mission_id) for mission_id in ids]
        missions = [value for value in values if value is not None]
        emit(
            ctx,
            {"ok": True, "missions": missions, "saved_ids": ids, "count": len(missions)},
            Panel(
                "\n".join(f"{item['id']}: {item['title']}" for item in missions)
                or "No saved mission templates.",
                title="Saved missions",
            ),
        )

    @engagement_app.command("mission-save")
    def engagement_save_mission(ctx: typer.Context, mission_id: str = typer.Argument(...)) -> None:
        """Save one guided mission template for quick recall."""
        from adaf_attack.core.engagement_dashboard import mission as find_mission
        from adaf_attack.core.user_config import set_saved_mission

        if find_mission(mission_id) is None:
            error = ActionableError(
                "UNKNOWN_MISSION",
                f"Unknown mission: {mission_id}",
                "Run `adaf-attack engagement missions` to list available missions.",
            )
            emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        saved = set_saved_mission(mission_id, saved=True)
        emit(
            ctx,
            {"ok": True, "mission": mission_id, "saved_ids": saved},
            Panel("Saved", title="Mission"),
        )

    @engagement_app.command("mission-remove")
    def engagement_remove_mission(
        ctx: typer.Context, mission_id: str = typer.Argument(...)
    ) -> None:
        """Remove one guided mission template from local saved missions."""
        from adaf_attack.core.user_config import set_saved_mission

        saved = set_saved_mission(mission_id, saved=False)
        emit(
            ctx,
            {"ok": True, "mission": mission_id, "saved_ids": saved},
            Panel("Removed", title="Mission"),
        )

    @engagement_app.command("asset")
    def engagement_asset(
        ctx: typer.Context,
        asset: str = typer.Argument(..., help="Asset, host, or node identifier to inspect."),
        session: Path = typer.Option(..., "--session"),
    ) -> None:
        """Show findings, graph relationships, actions, and safe access context for an asset."""
        from adaf_attack.core.asset_workspace import build_asset_workspace

        def human(payload: dict[str, Any]) -> str:
            summary = payload["summary"]
            return (
                f"Asset: {payload['asset']}\n"
                f"Nodes: {summary['nodes']}  Relationships: {summary['relationships']}\n"
                f"Findings: {summary['findings']}  Actions: {summary['actions']}\n"
                f"Recommended identity: {payload['access']['recommended_identity'] or 'none'}"
            )

        _run(ctx, "Asset workspace", session, lambda p: build_asset_workspace(p, asset), human)

    @engagement_app.command("identity")
    def engagement_identity(
        ctx: typer.Context,
        identity: str = typer.Argument(..., help="Identity or principal to inspect."),
        session: Path = typer.Option(..., "--session"),
    ) -> None:
        """Show identity control relationships, reachable assets, and credential context."""
        from adaf_attack.core.identity_workspace import build_identity_workspace

        def human(payload: dict[str, Any]) -> str:
            summary = payload["summary"]
            return (
                f"Identity: {payload['identity']}\n"
                f"Relationships: {summary['relationships']}  Reachable assets: {summary['reachable_assets']}\n"
                f"Findings: {summary['findings']}  Actions: {summary['actions']}\n"
                f"Credential lifecycle entries: {len(payload['credential_lifecycle'])}"
            )

        _run(
            ctx,
            "Identity workspace",
            session,
            lambda p: build_identity_workspace(p, identity),
            human,
        )

    @engagement_app.command("tier0")
    def engagement_tier0(
        ctx: typer.Context, session: Path = typer.Option(..., "--session")
    ) -> None:
        """Show Tier-0 nodes, control relationships, paths, and related findings."""
        from adaf_attack.core.tier0_workspace import build_tier0_workspace

        def human(payload: dict[str, Any]) -> str:
            summary = payload["summary"]
            return (
                f"Tier-0 nodes: {summary['nodes']}\n"
                f"Control relationships: {summary['relationships']}\n"
                f"Evidence-backed paths: {summary['paths']}\n"
                f"Related findings: {summary['findings']}"
            )

        _run(ctx, "Tier-0 workspace", session, build_tier0_workspace, human)

    @engagement_app.command("blast-radius")
    def engagement_blast_radius(
        ctx: typer.Context,
        principal: str = typer.Argument(..., help="Compromised identity or graph principal."),
        session: Path = typer.Option(..., "--session"),
        max_depth: int = typer.Option(6, "--max-depth", min=1, max=20),
    ) -> None:
        """Show reachable assets and high-value impact from a saved principal."""
        from adaf_attack.core.blast_radius_workspace import build_blast_radius_workspace

        def human(payload: dict[str, Any]) -> str:
            summary = payload["summary"]
            return (
                f"Principal: {payload['principal']}\n"
                f"Reachable nodes: {summary['reachable_nodes']}\n"
                f"High-value impacts: {summary['impacts']}\n"
                f"Related findings: {summary['findings']}"
            )

        _run(
            ctx,
            "Blast-radius workspace",
            session,
            lambda p: build_blast_radius_workspace(p, principal, max_depth=max_depth),
            human,
        )

    @engagement_app.command("domain")
    def engagement_domain(
        ctx: typer.Context, session: Path = typer.Option(..., "--session")
    ) -> None:
        """Show domain, forest, trust, asset, and Tier-0 posture from saved evidence."""
        from adaf_attack.core.domain_workspace import build_domain_workspace

        def human(payload: dict[str, Any]) -> str:
            summary = payload["summary"]
            return (
                f"Scope: {payload['scope']}\n"
                f"Domains: {summary['domains']}  Forests: {summary['forests']}\n"
                f"Assets: {summary['assets']}  Trusts: {summary['trusts']}\n"
                f"Tier-0 nodes: {summary['tier0']}  Findings: {summary['findings']}"
            )

        _run(ctx, "Domain workspace", session, build_domain_workspace, human)

    @engagement_app.command("investigation")
    def engagement_investigation(
        ctx: typer.Context, session: Path = typer.Option(..., "--session")
    ) -> None:
        """Show pinned findings, identities, assets, credentials, and evidence."""
        from adaf_attack.core.investigation_workspace import build_investigation_workspace

        def human(payload: dict[str, Any]) -> str:
            summary = payload["summary"]
            return (
                f"{payload['title']}\n"
                f"Pins: {summary['pins']}  Findings: {summary['findings']}  Nodes: {summary['nodes']}\n"
                f"Events: {summary['events']}  Evidence artifacts: {summary['artifacts']}"
            )

        _run(ctx, "Investigation workspace", session, build_investigation_workspace, human)

    @app.command("command-center")
    def command_center(ctx: typer.Context, session: Path = typer.Option(..., "--session")) -> None:
        """Open the polished mission-control view for an engagement."""
        from adaf_attack.core.product import command_center as build

        _run(
            ctx,
            "ADAF Command Center",
            session,
            build,
            lambda p: (
                f"{p['headline']}\nMode: {p['mode']}\nTimeline events: {p['timeline']['count']}\nReports ready: {'yes' if p['deliverables']['ready'] else 'not yet'}"
            ),
        )

    @app.command("impact-map")
    def impact_map(ctx: typer.Context, session: Path = typer.Option(..., "--session")) -> None:
        """Map evidence to findings, assets, paths, and business impact."""
        from adaf_attack.core.product import evidence_impact_map

        _run(
            ctx,
            "Evidence-to-impact map",
            session,
            evidence_impact_map,
            lambda p: f"Mapped findings: {p['count']}\nOffline evidence correlation complete.",
        )

    @app.command("investigate")
    def investigate(ctx: typer.Context, session: Path = typer.Option(..., "--session")) -> None:
        """Enter zero-noise read-only investigation mode over saved evidence."""
        from adaf_attack.core.product import zero_noise_investigation

        _run(
            ctx,
            "Zero-noise investigation",
            session,
            zero_noise_investigation,
            lambda p: (
                f"Artifacts: {len(p['artifacts'])}\nFindings: {p['finding_count']}\nNetwork contact: no\nTarget mutation: no"
            ),
        )

    @app.command("story")
    def story(ctx: typer.Context, session: Path = typer.Option(..., "--session")) -> None:
        """Build an executive story from technical findings."""
        from adaf_attack.core.product import executive_story

        _run(ctx, "Executive story", session, executive_story, lambda p: p["narrative"])

    @app.command("replay")
    def replay(
        ctx: typer.Context,
        session: Path = typer.Option(..., "--session"),
        limit: int = typer.Option(100, "--limit"),
    ) -> None:
        """Replay a session timeline for review and handoff."""
        from adaf_attack.core.standout_ux import session_timeline

        def human(payload: dict[str, Any]) -> str:
            events = payload.get("events")
            if not isinstance(events, list):
                return "No events recorded."
            return (
                "\n".join(
                    f"{event.get('time') or '-'}  {event.get('type', '-')}  {event.get('capability') or ''}"
                    for event in events[-12:]
                    if isinstance(event, dict)
                )
                or "No events recorded."
            )

        _run(ctx, "Engagement replay", session, session_timeline, human)

    @app.command("confidence")
    def confidence(ctx: typer.Context, session: Path = typer.Option(..., "--session")) -> None:
        """Show confidence quality and findings needing more evidence."""
        from adaf_attack.core.product import confidence_report

        _run(
            ctx,
            "Confidence report",
            session,
            confidence_report,
            lambda p: (
                f"Quality: {p['quality']}\nCounts: {p['confidence_counts']}\nNeeds more evidence: {', '.join(p['needs_more_evidence']) or 'none'}"
            ),
        )

    @app.command("product-templates")
    def templates(ctx: typer.Context) -> None:
        """List polished repeatable assessment templates."""
        from adaf_attack.core.product import product_templates

        templates = product_templates()
        payload = {"ok": True, "templates": templates}
        emit(
            ctx,
            payload,
            Panel(
                "\n".join(f"{item['id']}: {item['description']}" for item in templates),
                title="Assessment templates",
            ),
        )

    @app.command("deliverables")
    def deliverables(ctx: typer.Context, session: Path = typer.Option(..., "--session")) -> None:
        """Show the one-click client deliverables manifest."""
        from adaf_attack.core.product import deliverables_manifest

        _run(
            ctx,
            "Client deliverables",
            session,
            deliverables_manifest,
            lambda p: (
                f"Ready: {'yes' if p['ready'] else 'not yet'}\nAvailable: {', '.join(p['available']) or 'none'}\nGenerate: {p['generate_command']}"
            ),
        )
