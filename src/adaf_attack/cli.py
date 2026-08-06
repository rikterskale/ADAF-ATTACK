"""Main CLI entrypoint for ADAF-ATTACK."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel

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
    console.print(Panel.fit(
        "[bold green]ADAF-ATTACK doctor[/bold green]\n"
        "Local environment looks usable.\n"
        "(Full capability dependency checks will be added as modules land.)",
        title="Doctor",
    ))


@app.command("list-capabilities")
def list_capabilities() -> None:
    """List registered capabilities."""
    from adaf_attack.core.registry import capability_registry

    caps = capability_registry.list()
    if not caps:
        console.print("[yellow]No capabilities registered yet.[/yellow]")
        return

    for cap in caps:
        destructive = " [red]DESTRUCTIVE[/red]" if cap.destructive else ""
        console.print(f"  • [bold]{cap.id}[/bold] — {cap.summary}{destructive}")


if __name__ == "__main__":
    app()
