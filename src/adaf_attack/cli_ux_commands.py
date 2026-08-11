"""CLI UX command registration (profiles, demo, completions, session show)."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
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
) -> None:
    """Attach profile/demo/completions/session-show commands to the main CLI app."""
    _emit = emit
    _emit_error = emit_error
    _json_mode = json_mode
    _console = console

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

    @app.command("demo")
    def demo_cmd(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(
            None, "--workspace", help="Where to materialize the demo session."
        ),
    ) -> None:
        """Offline first-success path using packaged demo fixtures (no network)."""
        from adaf_attack.core.ux import session_findings_dashboard

        source = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "demo-session"
        if not source.is_dir():
            error = ActionableError(
                "DEMO_FIXTURES_MISSING",
                "Demo session fixtures are not available in this install.",
                "Run from a source checkout or reinstall the package with test fixtures.",
                suggested_command="adaf-attack doctor",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)

        dest_root = workspace or (default_workspace_dir() / "demo")
        dest = dest_root / "demo-session"
        if dest.exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, dest)
        session_meta = dest / "session.json"
        if not session_meta.is_file():
            session_meta.write_text(
                json.dumps(
                    {
                        "session_id": "demo-session",
                        "created_at": datetime.now(UTC).isoformat(),
                        "demo": True,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        dashboard = session_findings_dashboard(dest)
        payload = {
            "ok": True,
            "mode": "offline-demo",
            "session_path": str(dest),
            "dashboard": dashboard,
            "next_step": f"adaf-attack sessions show --session {dest}",
        }
        human = Panel(
            "\n".join(
                [
                    "Offline demo session materialized (no network contact).",
                    f"Session: {dest}",
                    f"Findings: {dashboard.get('finding_count', 0)}",
                    f"Graph nodes/edges: {dashboard.get('graph', {}).get('nodes', 0)} / {dashboard.get('graph', {}).get('edges', 0)}",
                    f"Next: adaf-attack sessions show --session {dest}",
                    "Or open the TUI: adaf-attack start",
                ]
            ),
            title="ADAF-ATTACK demo",
        )
        _emit(ctx, payload, human)

    @app.command("completions")
    def completions_cmd(
        ctx: typer.Context,
        shell: str = typer.Argument(..., help="bash | zsh | fish | powershell"),
    ) -> None:
        """Print a shell completion script for adaf-attack."""
        from adaf_attack.core.completions import (
            SUPPORTED_SHELLS,
            completion_install_hint,
            generate_completion,
        )

        try:
            script = generate_completion(shell)
        except ValueError as exc:
            error = ActionableError(
                "UNSUPPORTED_SHELL",
                str(exc),
                f"Choose one of: {', '.join(SUPPORTED_SHELLS)}",
                suggested_command="adaf-attack completions bash",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        if _json_mode(ctx):
            _emit(
                ctx,
                {
                    "ok": True,
                    "shell": shell,
                    "script": script,
                    "install_hint": completion_install_hint(shell),
                },
                "",
            )
            return
        typer.echo(script)
        if not _json_mode(ctx):
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
        from adaf_attack.core.ux import session_findings_dashboard

        if not session.is_dir():
            error = error_for("SESSION_NOT_FOUND", details={"session": str(session)})
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        dashboard = session_findings_dashboard(session, severity=severity, limit=limit)
        payload = {"ok": True, **dashboard}
        lines = [
            f"Session: {dashboard.get('session_id')}",
            f"Created: {dashboard.get('created_at') or 'unknown'}",
            f"Findings: {dashboard.get('finding_count', 0)}  Severity: {dashboard.get('severity') or {}}",
            f"Graph: {dashboard.get('graph', {}).get('nodes', 0)} nodes / {dashboard.get('graph', {}).get('edges', 0)} edges",
        ]
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
        human = Panel("\n".join(lines), title="Session findings dashboard")
        _emit(ctx, payload, human)
