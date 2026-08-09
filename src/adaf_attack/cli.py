"""Main CLI entrypoint for ADAF-ATTACK."""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from adaf_attack import __version__
from adaf_attack.core.auth import describe_auth
from adaf_attack.core.capability_help_data import capability_option_spec
from adaf_attack.core.cli_contract import ERROR_CATALOG, ActionableError, error_for
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.paths import (
    default_workspace_dir,
    platform_name,
    user_config_dir,
    user_data_dir,
)
from adaf_attack.core.runner import RunError, execute_capability
from adaf_attack.core.target import Target
from adaf_attack.core.user_config import load_user_config


def _workspace_is_empty(root: Path) -> bool:
    if not root.is_dir():
        return True
    for entry in root.iterdir():
        if entry.is_dir() and (entry / "session.json").is_file():
            return False
    return True


def _humanize_bytes(n: int) -> str:
    step = 1024.0
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < step or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} {unit}"
        n = int(n / step)
    return f"{n} B"


def _humanize_since(iso_or_ts: Any) -> str:
    if not iso_or_ts:
        return "unknown"
    try:
        dt = datetime.fromisoformat(str(iso_or_ts).replace("Z", "+00:00"))
    except ValueError:
        return str(iso_or_ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    delta = datetime.now(UTC) - dt
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    if seconds < 86400 * 30:
        return f"{seconds // 86400}d ago"
    return dt.date().isoformat()


def _parse_since(text: str) -> datetime:
    """Parse '2h', '7d', '30m', or ISO date/datetime into a UTC cutoff datetime."""
    text = text.strip()
    if not text:
        raise typer.BadParameter("--since cannot be empty")
    unit = text[-1].lower()
    if unit in {"s", "m", "h", "d"} and text[:-1].isdigit():
        n = int(text[:-1])
        factor = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
        return datetime.now(UTC).replace(microsecond=0) - _delta(n * factor)
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise typer.BadParameter(
            "--since must be N{s,m,h,d} or ISO datetime (e.g. 24h, 2026-08-01)"
        ) from exp
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _delta(seconds: int) -> timedelta:
    return timedelta(seconds=seconds)


def _path_status(path: Path) -> tuple[bool, bool]:
    exists = path.exists()
    if exists:
        return True, os.access(path, os.W_OK)
    parent = path.parent
    return False, parent.exists() and os.access(parent, os.W_OK)


app = typer.Typer(
    name="adaf-attack",
    help="Aggressive Active Directory offensive toolkit for senior internal red teamers.",
    no_args_is_help=True,
    invoke_without_command=True,
    rich_markup_mode="rich",
)
engagement_app = typer.Typer(help="Scoped engagement plans, execution, and report bundles.")
app.add_typer(engagement_app, name="engagement")


def _console(ctx: typer.Context) -> Console:
    config = ctx.ensure_object(dict)
    return Console(no_color=config.get("no_color", False), highlight=False)


def _json_mode(ctx: typer.Context) -> bool:
    return ctx.ensure_object(dict).get("output_format") == "json"


def _emit(ctx: typer.Context, payload: dict[str, Any], human: Any) -> None:
    if _json_mode(ctx):
        typer.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        _console(ctx).print(human)


def _emit_error(ctx: typer.Context, error: ActionableError) -> None:
    if _json_mode(ctx):
        typer.echo(json.dumps(error.payload(), indent=2, sort_keys=True))
    else:
        _console(ctx).print(
            f"Error [{error.code}]: {error.message}\nNext step: {error.remediation}"
        )


console = Console()


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-V", help="Show version and exit."),
    output_format: str = typer.Option("human", "--format", help="Output format: human or json."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable terminal color and styling."),
    non_interactive: bool = typer.Option(
        False, "--non-interactive", help="Never prompt; suitable for scripts and CI."
    ),
) -> None:
    if output_format not in {"human", "json"}:
        raise typer.BadParameter("must be 'human' or 'json'", param_hint="--format")
    ctx.ensure_object(dict).update(
        output_format=output_format,
        no_color=no_color or output_format == "json",
        non_interactive=non_interactive,
    )
    if version:
        _emit(ctx, {"ok": True, "version": __version__}, f"adaf-attack {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        _console(ctx).print(ctx.get_help())
        raise typer.Exit()
