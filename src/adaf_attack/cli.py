"""Main CLI entrypoint for ADAF-ATTACK."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from adaf_attack import __version__
from adaf_attack.core.auth import describe_auth
from adaf_attack.core.graph import AttackGraph
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
    invoke_without_command=True,
    rich_markup_mode="rich",
)
console = Console()


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-V", help="Show version and exit."),
) -> None:
    if version:
        console.print(f"adaf-attack {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
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

        checks.append("[green]✓[/green] impacket (kerberoast / ACL / ADCS / ticket auth)")
    except ImportError:
        checks.append(
            "[yellow]![/yellow] impacket (optional — pip install 'adaf-attack[kerberos]')"
        )

    try:
        import textual  # noqa: F401

        checks.append("[green]✓[/green] textual (TUI)")
    except ImportError:
        checks.append("[yellow]![/yellow] textual (optional — pip install 'adaf-attack[tui]')")

    if sys.platform == "win32":
        checks.append("[green]✓[/green] Windows path profile active (LOCALAPPDATA)")
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


def _build_target(
    domain: str,
    dc_ip: str,
    username: str | None,
    password: str | None,
    hashes: str | None,
    aes_key: str | None,
    ccache: str | None,
    use_kerberos: bool,
    ldaps: bool,
) -> Target:
    return Target(
        domain=domain,
        dc_ip=dc_ip,
        username=username,
        password=password,
        hashes=hashes,
        aes_key=aes_key,
        ccache=ccache,
        use_kerberos=use_kerberos,
        ldaps=ldaps,
    )


@app.command("run")
def run_capability(
    capability: str = typer.Argument(..., help="Capability ID (see list-capabilities)"),
    domain: str = typer.Option(..., "--domain", "-d", help="Target domain"),
    dc_ip: str = typer.Option(..., "--dc-ip", help="Domain controller IP or hostname"),
    username: str | None = typer.Option(None, "--username", "-u"),
    password: str | None = typer.Option(None, "--password", "-p"),
    hashes: str | None = typer.Option(None, "--hashes", help="LM:NT or NT hash"),
    aes_key: str | None = typer.Option(
        None, "--aes-key", help="AES128/256 key (hex) for Kerberos auth"
    ),
    ccache: str | None = typer.Option(
        None, "--ccache", help="Path to Kerberos ccache (sets KRB5CCNAME)"
    ),
    use_kerberos: bool = typer.Option(
        False, "-k", "--kerberos", help="Prefer Kerberos ticket auth (ccache / KRB5CCNAME)"
    ),
    ldaps: bool = typer.Option(False, "--ldaps", help="Use LDAPS"),
    force: bool = typer.Option(False, "--force", help="Required for destructive capabilities"),
    include_secrets: bool = typer.Option(
        False, "--include-secrets", help="Do not redact tickets/hashes in output"
    ),
    workspace: Path | None = typer.Option(
        None,
        "--workspace",
        help="Session root directory (default: platform data dir / workspaces)",
    ),
    graph: Path | None = typer.Option(
        None,
        "--graph",
        help="Existing graph.json for attack-paths (optional)",
    ),
    start: str | None = typer.Option(
        None,
        "--start",
        help="Start principal for attack-paths (SAM or node id)",
    ),
    max_depth: int = typer.Option(6, "--max-depth", help="Max path depth for ranking"),
    limit: int = typer.Option(25, "--limit", help="Max ranked paths to return"),
    creds_file: Path | None = typer.Option(
        None,
        "--creds-file",
        help="JSON file with multiple credentials (rotated until LDAP bind succeeds)",
    ),
    scope: str = typer.Option(
        "high-value",
        "--scope",
        help="ACL crawl scope: high-value (default) | domain | full",
    ),
    max_objects: int = typer.Option(
        500,
        "--max-objects",
        help="Max objects for domain-wide ACL crawl",
    ),
    template: str | None = typer.Option(
        None, "--template", help="Cert template name (cert-request / ESC1)"
    ),
    ca: str | None = typer.Option(None, "--ca", help="CA name for cert-request"),
    alt_name: str | None = typer.Option(
        None, "--alt-name", help="UPN/DNS alt name for ESC1-style request"
    ),
    write_target: str | None = typer.Option(
        None, "--write-target", help="SAM for shadow-creds write (requires --force)"
    ),
    set_on: str | None = typer.Option(
        None, "--set-on", help="Computer SAM for RBCD set target (requires --force)"
    ),
    set_from: str | None = typer.Option(
        None, "--set-from", help="Controlled computer SAM for RBCD set"
    ),
    sam: str | None = typer.Option(
        None, "--sam", help="Account SAM for pkinit-auth / shadow target"
    ),
    key: str | None = typer.Option(None, "--key", help="PEM private key for pkinit-auth"),
    cert: str | None = typer.Option(None, "--cert", help="PEM cert for pkinit-auth"),
    pfx: str | None = typer.Option(None, "--pfx", help="PFX path for pkinit-auth"),
    gpo: str | None = typer.Option(None, "--gpo", help="GPO CN/display name for sysvol stage"),
    payload: str | None = typer.Option(
        None, "--payload", help="File path or inline XML/script for GPO stage"
    ),
) -> None:
    """Run a capability against a target."""
    target = _build_target(
        domain, dc_ip, username, password, hashes, aes_key, ccache, use_kerberos, ldaps
    )

    console.print(
        Panel(
            f"[bold]{capability}[/bold]\n\n"
            f"Target: {domain} @ {dc_ip}\n"
            f"Auth: {describe_auth(target) if not creds_file else f'creds-file={creds_file} (rotation)'}",
            title="Running",
        )
    )

    extra: dict[str, Any] = {}
    if graph is not None:
        extra["graph_path"] = graph
    if start is not None:
        extra["start"] = start
    extra["max_depth"] = max_depth
    extra["limit"] = limit
    extra["scope"] = scope
    extra["max_objects"] = max_objects
    if template:
        extra["template"] = template
    if ca:
        extra["ca"] = ca
    if alt_name:
        extra["alt_name"] = alt_name
    if write_target:
        extra["write_target"] = write_target
    if set_on:
        extra["set_on"] = set_on
    if set_from:
        extra["set_from"] = set_from
    if sam:
        extra["sam"] = sam
    if key:
        extra["key"] = key
    if cert:
        extra["cert"] = cert
    if pfx:
        extra["pfx"] = pfx
    if gpo:
        extra["gpo"] = gpo
    if payload:
        from pathlib import Path as _P

        if payload.startswith("@"):
            extra["payload"] = _P(payload[1:]).read_text(encoding="utf-8")
        else:
            p = _P(payload)
            extra["payload"] = p.read_text(encoding="utf-8") if p.is_file() else payload

    try:
        out = execute_capability(
            capability,
            target,
            force=force,
            include_secrets=include_secrets,
            workspace=workspace,
            creds_file=creds_file,
            log=lambda m: console.print(f"[dim]{m}[/dim]"),
            **extra,
        )
        interesting = out.get("interesting") or {}
        top = interesting.get("top_paths") or []
        if top:
            console.print("\n[bold]Top ranked paths (sample)[/bold]")
            for ranked_path in top[:5]:
                console.print(
                    f"  score={ranked_path['score']:>5}  len={ranked_path['length']}  "
                    + " → ".join(x.split("@")[0] for x in ranked_path["path"][:6])
                )
        if out.get("cred_attempts"):
            console.print(f"[dim]Cred attempts: {out['cred_attempts']}[/dim]")
        if out.get("username"):
            console.print(f"[dim]Using principal: {out['username']} ({out.get('auth')})[/dim]")
        console.print(f"\n[green]Session:[/green] {out['session_path']}")
    except RunError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc


@app.command("rank-paths")
def rank_paths_cmd(
    graph: Path = typer.Option(..., "--graph", "-g", help="Path to graph.json"),
    start: str | None = typer.Option(None, "--start", "-s", help="Start principal (SAM or id)"),
    max_depth: int = typer.Option(6, "--max-depth"),
    limit: int = typer.Option(25, "--limit"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write ranked JSON here"),
) -> None:
    """Rank attack paths from a saved graph.json (offline, no DC contact)."""
    if not graph.is_file():
        console.print(f"[red]Graph not found:[/red] {graph}")
        raise typer.Exit(code=1)

    g = AttackGraph.from_file(graph)
    console.print(
        f"Loaded [cyan]{g.summary()['nodes']}[/cyan] nodes / "
        f"[cyan]{g.summary()['edges']}[/cyan] edges from {graph}"
    )

    starts = [start] if start else None
    ranked = g.rank_from_principals(starts, max_depth=max_depth, limit=limit)

    table = Table(title="Ranked attack paths", show_header=True, header_style="bold")
    table.add_column("#", style="dim", width=4)
    table.add_column("Score", justify="right")
    table.add_column("Len", justify="right")
    table.add_column("Path")

    for i, p in enumerate(ranked[:20], 1):
        short = " → ".join((x.split("@")[1] if "@" in x else x) for x in p["path"][:8])
        if len(p["path"]) > 8:
            short += " → …"
        table.add_row(str(i), f"{p['score']:.1f}", str(p["length"]), short)

    if ranked:
        console.print(table)
    else:
        console.print("[yellow]No paths found[/yellow]")

    payload = {"graph": str(graph), "start": start, "paths": ranked, "count": len(ranked)}
    if output:
        output.write_text(__import__("json").dumps(payload, indent=2) + "\n", encoding="utf-8")
        console.print(f"Wrote {output}")


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
