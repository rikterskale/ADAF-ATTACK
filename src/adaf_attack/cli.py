"""Main CLI entrypoint for ADAF-ATTACK.

Supports both pure CLI commands and an interactive Textual TUI (`start`).
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from adaf_attack import __version__

app = typer.Typer(
    name="adaf-attack",
    help="Aggressive Active Directory offensive toolkit for senior internal red teamers.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version and exit."
    ),
) -> None:
    """ADAF-ATTACK — Aggressive AD offensive toolkit."""
    if version:
        console.print(f"adaf-attack {__version__}")
        raise typer.Exit()


@app.command("doctor")
def doctor() -> None:
    """Check local prerequisites (no network)."""
    console.print(
        Panel.fit(
            "[bold green]ADAF-ATTACK doctor[/bold green]\n"
            "Local environment looks usable.\n"
            "(Full capability dependency checks will be added as modules land.)",
            title="Doctor",
        )
    )


@app.command("list-capabilities")
def list_capabilities() -> None:
    """List registered capabilities."""
    # Ensure capability modules are imported so they register themselves.
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
