"""Main CLI entrypoint for ADAF-ATTACK."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from adaf_attack import __version__
from adaf_attack.core.paths import (
    default_workspace_dir,
    platform_name,
    user_config_dir,
    user_data_dir,
)
from adaf_attack.core.runner import RunError, execute_capability
from adaf_attack.core.target import Target

app = typer.Typer(
    name="adaf-attack",
    help="Aggressive Active Directory offensive toolkit for senior internal red teamers.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", "-V", help="Show version and exit."),
) -> None:
    if version:
        console.print(f"adaf-attack {__version__}")
        raise typer.Exit()


@app.command("doctor")
def doctor() -> None:
    """Check local prerequisites (no network)."""
    checks: list[str] = []
    checks.append(f"Platform: [cyan]{platform_name()}[/cyan]  Python {sys.version.split()[0]}")
    checks.append(f"Data dir: {user_data_dir()}")
    checks.append(f"Config dir: {user_config_dir()}")
    checks.append(f"Default workspace: {default_workspace_dir()}")

    try:
        import ldap3  # noqa: F401

        checks.append("[green]✓[/green] ldap3")
    except ImportError:
        checks.append("[red]✗[/red] ldap3 (required)")

    try:
        import impacket  # noqa: F401

        checks.append("[green]✓[/green] impacket (kerberoast / ACL / ADCS SD)")
    except ImportError:
        checks.append("[yellow]![/yellow] impacket (optional — pip install 'adaf-attack[kerberos]')")

    try:
        import textual  # noqa: F401

        checks.append("[green]✓[/green] textual (TUI)")
    except ImportError:
        checks.append("[yellow]![/yellow] textual (optional — pip install 'adaf-attack[tui]')")

    if sys.platform == "win32":
        checks.append("[green]✓[/green] Windows path profile active (LOCALAPPDATA)")
        # Soft check for PowerShell
        checks.append(
            "[dim]PowerShell helpers: scripts\\Install-AdafAttack.ps1 , scripts\\AdafAttack.psm1[/dim]"
        )

    console.print(Panel("\n".join(checks), title="ADAF-ATTACK doctor", subtitle=f"v{__version__}"))


@app.command("list-capabilities")
def list_capabilities() -> None:
    """List registered capabilities."""
    import adaf_attack.capabilities  # noqa: F401
    from adaf_attack.core.registry import capability_registry

    caps = capability_registry.list()
    if not caps:
        console.print("[yellow]No capabilities registered yet.[/yellow]")
        return

    table = Table(title="Registered Capabilities", show_header=True, header_style="bold")
    table.add_column("ID", style="cyan")
    table.add_column("Category")
    table.add_column("Summary")
    table.add_column("Flags")

    for cap in caps:
        flags = ["[red]DESTRUCTIVE[/red]"] if cap.destructive else []
        table.add_row(cap.id, cap.category, cap.summary, " ".join(flags) or "-")

    console.print(table)


@app.command("paths")
def show_paths() -> None:
    """Show platform data / workspace paths."""
    table = Table(title="ADAF-ATTACK paths", show_header=True)
    table.add_column("Name")
    table.add_column("Path")
    table.add_row("platform", platform_name())
    table.add_row("data", str(user_data_dir()))
    table.add_row("config", str(user_config_dir()))
    table.add_row("workspace", str(default_workspace_dir()))
    console.print(table)


@app.command("run")
def run_capability(
    capability: str = typer.Argument(..., help="Capability ID (see list-capabilities)"),
    domain: str = typer.Option(..., "--domain", "-d", help="Target domain"),
    dc_ip: str = typer.Option(..., "--dc-ip", help="Domain controller IP or hostname"),
    username: Optional[str] = typer.Option(None, "--username", "-u"),
    password: Optional[str] = typer.Option(None, "--password", "-p"),
    hashes: Optional[str] = typer.Option(None, "--hashes", help="LM:NT or NT hash"),
    ldaps: bool = typer.Option(False, "--ldaps", help="Use LDAPS"),
    force: bool = typer.Option(False, "--force", help="Required for destructive capabilities"),
    include_secrets: bool = typer.Option(
        False, "--include-secrets", help="Do not redact tickets/hashes in output"
    ),
    workspace: Optional[Path] = typer.Option(
        None,
        "--workspace",
        help="Session root directory (default: platform data dir / workspaces)",
    ),
) -> None:
    """Run a capability against a target."""
    target = Target(
        domain=domain,
        dc_ip=dc_ip,
        username=username,
        password=password,
        hashes=hashes,
        ldaps=ldaps,
    )

    console.print(
        Panel(
            f"[bold]{capability}[/bold]\n\nTarget: {domain} @ {dc_ip}",
            title="Running",
        )
    )

    try:
        out = execute_capability(
            capability,
            target,
            force=force,
            include_secrets=include_secrets,
            workspace=workspace,
            log=lambda m: console.print(f"[dim]{m}[/dim]"),
        )
        interesting = out.get("interesting") or {}
        top = interesting.get("top_paths") or []
        if top:
            console.print("\n[bold]Top ranked paths (sample)[/bold]")
            for p in top[:5]:
                console.print(
                    f"  score={p['score']:>5}  len={p['length']}  "
                    + " → ".join(x.split("@")[0] for x in p["path"][:6])
                )
        console.print(f"\n[green]Session:[/green] {out['session_path']}")
    except RunError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc


@app.command("start")
def start() -> None:
    """Launch the interactive Textual TUI shell."""
    try:
        from adaf_attack.tui.app import run_tui
    except ImportError as exc:
        console.print(
            "[red]Textual is required for the interactive shell.[/red]\n"
            "Install with: [bold]pip install 'adaf-attack[tui]'[/bold]"
        )
        raise typer.Exit(code=1) from exc

    run_tui()


if __name__ == "__main__":
    app()
