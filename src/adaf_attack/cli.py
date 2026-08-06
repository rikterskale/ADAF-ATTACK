"""Main CLI entrypoint for ADAF-ATTACK.

Supports both pure CLI commands and an interactive Textual TUI (`start`).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from adaf_attack import __version__
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
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
    """ADAF-ATTACK — Aggressive AD offensive toolkit."""
    if version:
        console.print(f"adaf-attack {__version__}")
        raise typer.Exit()


@app.command("doctor")
def doctor() -> None:
    """Check local prerequisites (no network)."""
    checks = []
    try:
        import ldap3  # noqa: F401

        checks.append(("[green]✓[/green] ldap3"))
    except ImportError:
        checks.append("[red]✗[/red] ldap3 (required)")

    try:
        import impacket  # noqa: F401

        checks.append("[green]✓[/green] impacket (kerberoast / asrep)")
    except ImportError:
        checks.append("[yellow]![/yellow] impacket (optional — pip install 'adaf-attack[kerberos]')")

    try:
        import textual  # noqa: F401

        checks.append("[green]✓[/green] textual (TUI)")
    except ImportError:
        checks.append("[yellow]![/yellow] textual (optional — pip install 'adaf-attack[tui]')")

    console.print(
        Panel("\n".join(checks), title="ADAF-ATTACK doctor", subtitle=f"v{__version__}")
    )


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
        flags = []
        if cap.destructive:
            flags.append("[red]DESTRUCTIVE[/red]")
        table.add_row(cap.id, cap.category, cap.summary, " ".join(flags) or "-")

    console.print(table)


@app.command("run")
def run_capability(
    capability: str = typer.Argument(..., help="Capability ID (see list-capabilities)"),
    domain: str = typer.Option(..., "--domain", "-d", help="Target domain (e.g. corp.local)"),
    dc_ip: str = typer.Option(..., "--dc-ip", help="Domain controller IP or hostname"),
    username: Optional[str] = typer.Option(None, "--username", "-u"),
    password: Optional[str] = typer.Option(None, "--password", "-p"),
    hashes: Optional[str] = typer.Option(None, "--hashes", help="LM:NT or NT hash"),
    ldaps: bool = typer.Option(False, "--ldaps", help="Use LDAPS"),
    force: bool = typer.Option(False, "--force", help="Required for destructive capabilities"),
    include_secrets: bool = typer.Option(
        False, "--include-secrets", help="Do not redact tickets/hashes in output"
    ),
    workspace: Path = typer.Option(Path("workspaces"), "--workspace", help="Session root directory"),
) -> None:
    """Run a capability against a target."""
    import adaf_attack.capabilities  # noqa: F401
    from adaf_attack.core.registry import capability_registry

    cap = capability_registry.get(capability)
    if cap is None:
        console.print(f"[red]Unknown capability:[/red] {capability}")
        console.print("Run [bold]adaf-attack list-capabilities[/bold] to see available IDs.")
        raise typer.Exit(code=1)

    if cap.destructive and not force:
        console.print(
            f"[red]Capability '{capability}' is marked DESTRUCTIVE.[/red]\n"
            "Re-run with [bold]--force[/bold] if you intend to proceed."
        )
        raise typer.Exit(code=2)

    if cap.runner is None:
        console.print(f"[red]Capability '{capability}' has no runner implemented yet.[/red]")
        raise typer.Exit(code=1)

    target = Target(
        domain=domain,
        dc_ip=dc_ip,
        username=username,
        password=password,
        hashes=hashes,
        ldaps=ldaps,
    )
    session = Session(base_dir=workspace)
    graph = AttackGraph()

    console.print(
        Panel(
            f"[bold]{cap.id}[/bold]\n{cap.summary}\n\n"
            f"Target: {domain} @ {dc_ip}\n"
            f"Session: {session.session_id}",
            title="Running",
        )
    )

    session.log(
        "run.start",
        capability=capability,
        domain=domain,
        dc_ip=dc_ip,
        username=username,
    )

    try:
        result = cap.runner.run(
            target,
            session,
            graph,
            include_secrets=include_secrets,
            force=force,
        )
        session.log("run.complete", capability=capability, ok=True)
        console.print(f"\n[green]Session directory:[/green] {session.root}")
    except Exception as exc:
        session.log("run.error", capability=capability, error=str(exc))
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
