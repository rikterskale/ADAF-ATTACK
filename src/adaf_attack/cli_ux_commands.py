"""CLI UX command registration (profiles, demo, completions, session show)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from rich.panel import Panel
from rich.table import Table

from adaf_attack.core.cli_contract import ActionableError, error_for
from adaf_attack.core.paths import default_workspace_dir


def register_ux_commands(
    app: typer.Typer,
    session_app: typer.Typer,
    *,
    emit: Callable[..., None],
    emit_error: Callable[..., None],
    json_mode: Callable[..., bool],
    console: Callable[..., Any],
    doctor_payload: Callable[..., dict[str, Any]],
) -> None:
    """Attach profile/demo/completions/session-show commands to the main CLI app."""
    _emit = emit
    _emit_error = emit_error
    _json_mode = json_mode
    _console = console

    @app.command("quickstart", rich_help_panel="Setup & diagnostics")
    def quickstart_cmd(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(
            None, "--workspace", help="Where to create the disposable offline demo session."
        ),
    ) -> None:
        """Run the complete safe first-install check and offline demo."""
        from adaf_attack.core.ux import session_findings_dashboard
        from adaf_attack.demo import materialize_demo_session

        doctor = doctor_payload("user-readiness")
        if not doctor["ok"]:
            payload = {
                "ok": False,
                "stage": "doctor",
                "doctor": doctor,
                "next_step": "Run `adaf-attack paths --repair`, then rerun `adaf-attack quickstart`.",
            }
            _emit(
                ctx,
                payload,
                Panel(
                    f"Quickstart stopped at doctor.\nNext: {payload['next_step']}",
                    title="ADAF-ATTACK quickstart",
                ),
            )
            raise typer.Exit(code=1)

        dest_root = workspace or (default_workspace_dir() / "quickstart")
        dest = dest_root / "demo-session"
        if dest.exists():
            error = ActionableError(
                "QUICKSTART_WORKSPACE_EXISTS",
                f"The quickstart session already exists: {dest}",
                "Choose an empty directory with `--workspace <path>` or remove the disposable quickstart session yourself.",
                suggested_command="adaf-attack quickstart --workspace ./quickstart-2",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        try:
            materialize_demo_session(dest)
        except (OSError, FileNotFoundError) as exc:
            error = ActionableError(
                "QUICKSTART_WRITE_FAILED",
                f"Could not create the quickstart demo session: {exc}",
                "Choose a writable directory with `adaf-attack paths` and rerun `adaf-attack quickstart --workspace <path>`.",
                suggested_command="adaf-attack paths",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc

        dashboard = session_findings_dashboard(dest)
        payload = {
            "ok": True,
            "stage": "complete",
            "checks": [
                "doctor --profile user-readiness",
                "packaged demo fixtures",
                "offline demo session",
            ],
            "doctor": doctor,
            "session_path": str(dest),
            "dashboard": dashboard,
            "next_steps": [
                f"adaf-attack session show --session {dest}",
                f"adaf-attack engagement report --session {dest} --engagement-id QUICKSTART-2026-001",
                "Read docs/USER_READINESS.md before connecting to an authorized target.",
            ],
        }
        _emit(
            ctx,
            payload,
            Panel(
                "Installation and offline demo passed.\n"
                f"Session: {dest}\n"
                f"Findings: {dashboard.get('finding_count', 0)}\n"
                f"Next: adaf-attack session show --session {dest}",
                title="ADAF-ATTACK quickstart",
            ),
        )

    @app.command("start-here", hidden=True)
    def start_here_cmd(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(
            None, "--workspace", help="Where to create the disposable offline demo session."
        ),
    ) -> None:
        """Beginner-friendly alias for the safe first-install flow."""
        quickstart_cmd(ctx, workspace)

    @app.command("explain", rich_help_panel="Guidance & UX helpers")
    def explain_cmd(
        ctx: typer.Context,
        capability: str = typer.Argument(..., help="Capability ID to explain in plain language."),
    ) -> None:
        """Explain what a capability does, its safety level, and what to do first."""
        from adaf_attack.core.capability_help_data import capability_option_spec
        from adaf_attack.core.novice import capability_difficulty, plain_description, safety_summary
        from adaf_attack.core.registry import capability_registry
        from adaf_attack.core.ux import build_ready_command, capability_prerequisites

        cap = capability_registry.get(capability)
        if cap is None:
            error = ActionableError(
                "UNKNOWN_CAPABILITY",
                f"Unknown capability: {capability}",
                "Run `adaf-attack list-capabilities --novice` to browse beginner-friendly capabilities.",
                suggested_command="adaf-attack list-capabilities --novice --safe-only",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        safety = safety_summary(cap)
        difficulty = capability_difficulty(cap)
        spec = capability_option_spec(cap.id, cap.requires_force)
        prerequisites = capability_prerequisites(cap.id)
        payload = {
            "ok": True,
            "capability": {
                "id": cap.id,
                "summary": cap.summary,
                "plain_description": plain_description(cap),
                "category": cap.category,
                "safety": safety,
                "difficulty": difficulty,
                "required_options": list(spec.required),
                "optional_options": list(spec.optional),
                "prerequisites": prerequisites,
                "next_command": build_ready_command(cap.id),
            },
        }
        human = Panel(
            f"{plain_description(cap)}\n\n"
            f"Safety: {safety['level']} — {safety['plain']}\n"
            f"Difficulty: {difficulty['level']} — {difficulty['reason']}\n"
            f"Required information: {', '.join(spec.required) or 'none'}\n"
            f"Best run after: {', '.join(prerequisites['best_run_after']) or 'none'}\n\n"
            "Next: review the plan with `adaf-attack plan <id> -d <domain> --dc-ip <dc>`.",
            title=f"Plain-language explanation: {cap.id}",
        )
        _emit(ctx, payload, human)

    @app.command("what-next", rich_help_panel="Guidance & UX helpers")
    def what_next_cmd(
        ctx: typer.Context,
        capability: str | None = typer.Argument(None, help="Capability just completed, if known."),
        safe_only: bool = typer.Option(
            True, "--safe-only/--include-advanced", help="Prefer beginner-safe suggestions."
        ),
        session: Path | None = typer.Option(
            None, "--session", help="Rank actions using persisted session evidence."
        ),
        mode: str = typer.Option(
            "OBSERVE", "--mode", help="Operational mode: OBSERVE, VALIDATE, or EMULATE."
        ),
        rank_by: str = typer.Option(
            "balanced", "--rank-by", help="Ranking mode for session recommendations."
        ),
    ) -> None:
        """Recommend the next action using capability or engagement context."""
        from adaf_attack.core.novice import beginner_next_actions, home_actions

        if session is not None:
            from adaf_attack.core.engagement_dashboard import dashboard

            view = dashboard(session, mode=mode, ranking=rank_by)
            actions = view["recommended_next_actions"]
            payload = {
                "ok": True,
                "context": "session",
                "session": str(session),
                "mode": view["engagement"]["mode"],
                "ranking": view["ranking"],
                "objective": view["objective"],
                "breadcrumbs": view["breadcrumbs"],
                "suggestions": actions,
            }
            human = Panel(
                "\n".join(
                    f"{i}. {item['action']} [{item['risk']}]\n   {item['why']}"
                    for i, item in enumerate(actions, 1)
                )
                or "No next action is recommended.",
                title="What next for this engagement?",
            )
            _emit(ctx, payload, human)
            return

        if capability is None:
            actions = home_actions(first_run=True)
            payload = {"ok": True, "context": "new-user", "suggestions": actions}
            human = Panel(
                "\n".join(
                    f"{i + 1}. {item['goal']}\n   {item['command']}\n   {item['why']}"
                    for i, item in enumerate(actions)
                ),
                title="What should I do next?",
            )
            _emit(ctx, payload, human)
            return
        from adaf_attack.core.registry import capability_registry

        cap = capability_registry.get(capability)
        if cap is None:
            error = ActionableError(
                "UNKNOWN_CAPABILITY",
                f"Unknown capability: {capability}",
                "Run `adaf-attack list-capabilities --novice` to find a valid capability.",
                suggested_command="adaf-attack list-capabilities --novice",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        suggestions = beginner_next_actions(cap)
        if safe_only:
            from adaf_attack.core.novice import safety_summary

            suggestions = [
                item
                for item in suggestions
                if (follow := capability_registry.get(item["id"])) is not None
                and safety_summary(follow)["level"] != "RED"
            ]
        payload = {"ok": True, "context": capability, "suggestions": suggestions}
        human = Panel(
            "\n".join(
                f"{i + 1}. {item['id']} — {item['message']}" for i, item in enumerate(suggestions)
            )
            or "No follow-up is recommended yet. Review the session findings first.",
            title=f"What next after {capability}?",
        )
        _emit(ctx, payload, human)

    # --- Profile management (named target + opsec profiles) --------------------
    profile_app = typer.Typer(help="Named target and opsec profiles.")
    app.add_typer(profile_app, name="profile")

    @profile_app.command("list")
    def profile_list(ctx: typer.Context) -> None:
        """List saved target profiles."""
        from adaf_attack.core.profiles import list_profiles
        from adaf_attack.core.user_config import get_key

        profiles = list_profiles()
        default_name = get_key("profile.default")
        payload = {
            "ok": True,
            "default": default_name,
            "profiles": [{**p, "is_default": p.get("name") == default_name} for p in profiles],
            "count": len(profiles),
        }
        if not profiles:
            human: Any = Panel(
                "No profiles saved.\nCreate one with: adaf-attack profile set lab --domain corp.lab --dc-ip 10.0.0.10",
                title="Profiles",
            )
        else:
            table = Table(title="Target profiles", show_header=True)
            table.add_column("Name")
            table.add_column("Domain")
            table.add_column("DC")
            table.add_column("User")
            table.add_column("Opsec")
            table.add_column("Default")
            for p in profiles:
                table.add_row(
                    str(p.get("name") or "-"),
                    str(p.get("domain") or "-"),
                    str(p.get("dc_ip") or "-"),
                    str(p.get("username") or "-"),
                    str(p.get("opsec_profile") or "balanced"),
                    "yes" if p.get("name") == default_name else "-",
                )
            human = table
        _emit(ctx, payload, human)

    @profile_app.command("show")
    def profile_show(ctx: typer.Context, name: str = typer.Argument(...)) -> None:
        """Show one profile."""
        from adaf_attack.core.profiles import get_profile

        profile = get_profile(name)
        if profile is None:
            error = ActionableError(
                "UNKNOWN_PROFILE",
                f"Unknown profile: {name}",
                "Run `adaf-attack profile list` to see saved profiles.",
                suggested_command="adaf-attack profile list",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        payload = {"ok": True, "profile": {"name": name, **profile}}
        human = Panel(
            "\n".join(
                [
                    f"Name: {name}",
                    f"Domain: {profile.get('domain') or '-'}",
                    f"DC: {profile.get('dc_ip') or '-'}",
                    f"Username: {profile.get('username') or '-'}",
                    f"Opsec: {profile.get('opsec_profile') or 'balanced'}",
                    f"LDAPS: {profile.get('ldaps', False)}",
                    f"Kerberos: {profile.get('kerberos', False)}",
                    f"Notes: {profile.get('notes') or '-'}",
                ]
            ),
            title=f"Profile: {name}",
        )
        _emit(ctx, payload, human)

    @profile_app.command("set")
    def profile_set(
        ctx: typer.Context,
        name: str = typer.Argument(..., help="Profile name."),
        domain: str = typer.Option("", "--domain", "-d"),
        dc_ip: str = typer.Option("", "--dc-ip"),
        username: str = typer.Option("", "--username", "-u"),
        opsec: str = typer.Option("balanced", "--opsec", help="stealth | balanced | loud"),
        ldaps: bool = typer.Option(False, "--ldaps"),
        kerberos: bool = typer.Option(False, "--kerberos"),
        notes: str = typer.Option("", "--notes"),
        make_default: bool = typer.Option(False, "--default", help="Also mark as default profile."),
    ) -> None:
        """Create or update a named target profile."""
        from adaf_attack.core.profiles import VALID_OPSEC, apply_profile_to_defaults, set_profile
        from adaf_attack.core.user_config import set_key

        if opsec not in VALID_OPSEC:
            error = ActionableError(
                "INVALID_OPSEC_PROFILE",
                f"Invalid opsec profile: {opsec}",
                f"Choose one of: {', '.join(VALID_OPSEC)}",
                suggested_command="adaf-attack profile set lab --opsec balanced",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        values = {
            "domain": domain,
            "dc_ip": dc_ip,
            "username": username,
            "opsec_profile": opsec,
            "ldaps": ldaps,
            "kerberos": kerberos,
            "notes": notes,
        }
        values = {k: v for k, v in values.items() if v != "" and v is not None}
        try:
            saved = set_profile(name, values)
        except ValueError as exc:
            error = ActionableError(
                "INVALID_PROFILE",
                str(exc),
                "Correct the profile fields and try again.",
                suggested_command="adaf-attack profile list",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        if make_default:
            set_key("profile.default", name)
            apply_profile_to_defaults(name)
        payload = {"ok": True, "profile": {"name": name, **saved}, "default": make_default}
        _emit(
            ctx,
            payload,
            Panel(
                f"Saved profile '{name}'\nDomain: {domain or '-'}  DC: {dc_ip or '-'}  Opsec: {opsec}",
                title="Profile saved",
            ),
        )

    @profile_app.command("use")
    def profile_use(ctx: typer.Context, name: str = typer.Argument(...)) -> None:
        """Activate a profile as the default for subsequent commands."""
        from adaf_attack.core.profiles import apply_profile_to_defaults, get_profile
        from adaf_attack.core.user_config import set_key

        profile = get_profile(name)
        if profile is None:
            error = ActionableError(
                "UNKNOWN_PROFILE",
                f"Unknown profile: {name}",
                "Run `adaf-attack profile list` to see saved profiles.",
                suggested_command="adaf-attack profile list",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        set_key("profile.default", name)
        applied = apply_profile_to_defaults(name)
        _emit(
            ctx,
            {"ok": True, "profile": {"name": name, **profile}, "config": applied},
            Panel(
                f"Active profile: {name}\nDomain: {profile.get('domain') or '-'} @ {profile.get('dc_ip') or '-'}\nOpsec: {profile.get('opsec_profile') or 'balanced'}",
                title="Profile activated",
            ),
        )

    @profile_app.command("delete")
    def profile_delete(ctx: typer.Context, name: str = typer.Argument(...)) -> None:
        """Delete a saved profile."""
        from adaf_attack.core.profiles import delete_profile
        from adaf_attack.core.user_config import get_key, load_user_config, save_user_config

        if not delete_profile(name):
            error = ActionableError(
                "UNKNOWN_PROFILE",
                f"Unknown profile: {name}",
                "Run `adaf-attack profile list` to see saved profiles.",
                suggested_command="adaf-attack profile list",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        if get_key("profile.default") == name:
            data = load_user_config()
            data.pop("profile.default", None)
            save_user_config(data)
        _emit(
            ctx, {"ok": True, "deleted": name}, Panel(f"Deleted profile '{name}'", title="Profile")
        )

    @profile_app.command("default")
    def profile_default(
        ctx: typer.Context,
        name: str | None = typer.Argument(None, help="Profile name; omit to clear default."),
    ) -> None:
        """Set or clear the default profile."""
        from adaf_attack.core.profiles import get_profile
        from adaf_attack.core.user_config import (
            load_user_config,
            save_user_config,
            set_key,
        )

        if name is None:
            data = load_user_config()
            data.pop("profile.default", None)
            save_user_config(data)
            _emit(
                ctx,
                {"ok": True, "default": None},
                Panel("Default profile cleared", title="Profile"),
            )
            return
        if get_profile(name) is None:
            error = ActionableError(
                "UNKNOWN_PROFILE",
                f"Unknown profile: {name}",
                "Run `adaf-attack profile list` to see saved profiles.",
                suggested_command="adaf-attack profile list",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        set_key("profile.default", name)
        _emit(
            ctx,
            {"ok": True, "default": name, "profile": get_profile(name)},
            Panel(f"Default profile: {name}", title="Profile"),
        )

    @app.command("demo", rich_help_panel="Setup & diagnostics")
    def demo_cmd(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(
            None, "--workspace", help="Where to materialize the demo session."
        ),
    ) -> None:
        """Offline first-success path using packaged demo fixtures (no network)."""
        from adaf_attack.core.ux import session_findings_dashboard

        dest_root = workspace or (default_workspace_dir() / "demo")
        dest = dest_root / "demo-session"
        if dest.exists():
            import shutil

            shutil.rmtree(dest)
        from adaf_attack.demo import materialize_demo_session

        try:
            materialize_demo_session(dest)
        except (OSError, FileNotFoundError) as exc:
            error = ActionableError(
                "DEMO_FIXTURES_MISSING",
                f"Could not create the packaged demo session: {exc}",
                "Choose a writable workspace and rerun `adaf-attack demo`.",
                suggested_command="adaf-attack paths",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        dashboard = session_findings_dashboard(dest)
        payload = {
            "ok": True,
            "mode": "offline-demo",
            "session_path": str(dest),
            "dashboard": dashboard,
            "next_step": f"adaf-attack session show --session {dest}",
        }
        human = Panel(
            "\n".join(
                [
                    "Offline demo session materialized (no network contact).",
                    f"Session: {dest}",
                    f"Findings: {dashboard.get('finding_count', 0)}",
                    f"Graph nodes/edges: {dashboard.get('graph', {}).get('nodes', 0)} / {dashboard.get('graph', {}).get('edges', 0)}",
                    f"Next: adaf-attack session show --session {dest}",
                    "Or open the TUI: adaf-attack start",
                ]
            ),
            title="ADAF-ATTACK demo",
        )
        _emit(ctx, payload, human)

    @app.command("start-demo", hidden=True)
    def start_demo_cmd(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(
            None, "--workspace", help="Where to materialize the demo session."
        ),
    ) -> None:
        """Start the safe offline demo."""
        demo_cmd(ctx, workspace)

    @app.command("completions", rich_help_panel="Setup & diagnostics")
    def completions_cmd(
        ctx: typer.Context,
        shell: str = typer.Argument(
            "bash",
            help="bash | zsh | fish | powershell (ignored when --all is set)",
        ),
        emit_all: bool = typer.Option(
            False, "--all", help="Emit scripts for every supported shell."
        ),
        output_dir: Path | None = typer.Option(
            None,
            "--output-dir",
            help="Write scripts as adaf-attack.<shell> under this directory instead of stdout.",
        ),
    ) -> None:
        """Print (or write) shell completion scripts for adaf-attack."""
        from adaf_attack.core.completions import (
            SUPPORTED_SHELLS,
            completion_install_hint,
            generate_completion,
        )

        shells = list(SUPPORTED_SHELLS) if emit_all else [shell]

        scripts: dict[str, str] = {}
        for sh in shells:
            try:
                scripts[sh] = generate_completion(sh)
            except ValueError as exc:
                error = ActionableError(
                    "UNSUPPORTED_SHELL",
                    str(exc),
                    f"Choose one of: {', '.join(SUPPORTED_SHELLS)}",
                    suggested_command="adaf-attack completions bash",
                )
                _emit_error(ctx, error)
                raise typer.Exit(code=error.exit_code) from exc

        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            written: list[str] = []
            for sh, script in scripts.items():
                extension = {"bash": "bash", "zsh": "zsh", "fish": "fish", "powershell": "ps1"}[sh]
                path = output_dir / f"adaf-attack.{extension}"
                path.write_text(script, encoding="utf-8")
                written.append(str(path))
            payload = {
                "ok": True,
                "written": written,
                "install_hints": {sh: completion_install_hint(sh) for sh in shells},
            }
            _emit(
                ctx,
                payload,
                Panel(
                    "\n".join(f"wrote {p}" for p in written),
                    title="Completion scripts",
                ),
            )
            return

        if _json_mode(ctx):
            if emit_all:
                _emit(
                    ctx,
                    {
                        "ok": True,
                        "scripts": scripts,
                        "install_hints": {sh: completion_install_hint(sh) for sh in shells},
                    },
                    "",
                )
            else:
                _emit(
                    ctx,
                    {
                        "ok": True,
                        "shell": shell,
                        "script": scripts[shell],
                        "install_hint": completion_install_hint(shell),
                    },
                    "",
                )
            return

        if emit_all:
            for sh, script in scripts.items():
                typer.echo(f"# ---- {sh} ----")
                typer.echo(script)
                _console(ctx).print(
                    f"[dim]# Install hint ({sh}): {completion_install_hint(sh)}[/dim]"
                )
        else:
            typer.echo(scripts[shell])
            _console(ctx).print(f"[dim]# Install hint: {completion_install_hint(shell)}[/dim]")

    @session_app.command("show")
    def session_show(
        ctx: typer.Context,
        session: Path = typer.Option(..., "--session", help="Session directory to inspect."),
        severity: str | None = typer.Option(
            None, "--severity", help="Filter findings by severity."
        ),
        limit: int = typer.Option(50, "--limit"),
    ) -> None:
        """Show a richer findings dashboard for one session."""
        import json

        from adaf_attack.core.ux import session_findings_dashboard

        if not session.is_dir():
            error = error_for("SESSION_NOT_FOUND", details={"session": str(session)})
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        dashboard = session_findings_dashboard(session, severity=severity, limit=limit)
        try:
            outcome = json.loads((session / "outcome.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            outcome = None
        timeline: list[dict[str, Any]] = []
        events = session / "events.jsonl"
        if events.is_file():
            try:
                for line in events.read_text(encoding="utf-8").splitlines()[-25:]:
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(item, dict):
                        timeline.append(
                            {
                                "time": item.get("time") or item.get("timestamp"),
                                "event": item.get("event") or item.get("type") or "event",
                                "capability": item.get("capability"),
                            }
                        )
            except OSError:
                timeline = []
        payload = {
            "ok": True,
            **dashboard,
            "timeline": timeline,
            "outcome": outcome,
            "resume_command": f"adaf-attack session show --session {session}",
        }
        finding_count = dashboard.get("finding_count", 0)
        severity_counts = dashboard.get("severity") or {}
        severity_display = severity_counts if severity_counts else "none"
        lines = [
            f"Session: {dashboard.get('session_id')}",
            f"Created: {dashboard.get('created_at') or 'unknown'}",
            f"Findings: {finding_count}  Severity: {severity_display}",
            f"Graph: {dashboard.get('graph', {}).get('nodes', 0)} nodes / {dashboard.get('graph', {}).get('edges', 0)} edges",
            f"Outcome: {outcome.get('status')}  Rollback: {outcome.get('rollback', {}).get('status')}"
            if isinstance(outcome, dict)
            else "Outcome: not recorded",
            f"Detection: {outcome.get('detection', {}).get('status', 'not-recorded')}"
            if isinstance(outcome, dict)
            else "Detection: not recorded",
            f"Resume: adaf-attack session show --session {session}",
        ]
        if finding_count == 0:
            lines.append(
                "Empty: populate this session with `adaf-attack demo --workspace <dir>`"
                " or run a discovery capability."
            )
        titles = dashboard.get("titles") or []
        if titles:
            lines.append("Titles:")
            for title in titles[:10]:
                lines.append(f"  - {title}")
        top_paths = dashboard.get("top_paths") or []
        if top_paths:
            lines.append("Top paths:")
            for path_item in top_paths[:5]:
                if isinstance(path_item, dict):
                    nodes = path_item.get("path") or []
                    short = " -> ".join(str(x).split("@")[0] for x in nodes[:6])
                    lines.append(f"  score={path_item.get('score', '?')}  {short}")
        if timeline:
            lines.append("Timeline:")
            for item in timeline[-5:]:
                label = item.get("event") or "event"
                cap = f" ({item['capability']})" if item.get("capability") else ""
                lines.append(f"  - {item.get('time') or 'unknown'}: {label}{cap}")
        human = Panel("\n".join(lines), title="Session findings dashboard")
        _emit(ctx, payload, human)

    @session_app.command("access")
    def session_access(
        ctx: typer.Context,
        session: Path = typer.Option(..., "--session", help="Session directory to inspect."),
    ) -> None:
        """Show safe identity, authentication, and credential-context metadata."""
        from adaf_attack.core.access_context import session_access_context

        if not session.is_dir():
            error = error_for("SESSION_NOT_FOUND", details={"session": str(session)})
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        payload = session_access_context(session)
        identities = payload["identities"]
        human = Panel(
            "Recommended identity: "
            + str(payload["recommended_identity"] or "not recorded")
            + "\n\n"
            + (
                "\n".join(
                    f"{item['identity']} — {', '.join(item['auth_modes']) or 'auth not recorded'}"
                    for item in identities
                )
                or "No identities recorded."
            )
            + f"\n\nCredential artifacts: {len(payload['credential_artifacts'])}\n{payload['safety']}",
            title="Session access context",
        )
        _emit(ctx, payload, human)
