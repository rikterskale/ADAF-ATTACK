"""Main CLI entrypoint for ADAF-ATTACK."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from adaf_attack import __version__
from adaf_attack.core.auth import describe_auth
from adaf_attack.core.cli_contract import ActionableError, error_for
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


@app.command("doctor")
def doctor(
    ctx: typer.Context,
    explain: bool = typer.Option(False, "--explain", help="Include remediation for every check."),
) -> None:
    """Check local prerequisites (no network)."""
    checks: list[dict[str, Any]] = [
        {"id": "platform", "status": "ok", "value": platform_name(), "remediation": None},
        {"id": "python", "status": "ok", "value": sys.version.split()[0], "remediation": None},
        {"id": "data_dir", "status": "ok", "value": str(user_data_dir()), "remediation": None},
        {"id": "config_dir", "status": "ok", "value": str(user_config_dir()), "remediation": None},
        {
            "id": "workspace",
            "status": "ok",
            "value": str(default_workspace_dir()),
            "remediation": None,
        },
    ]
    for package, optional, remediation in (
        ("ldap3", False, "Install the base package dependencies: pip install -e ."),
        ("impacket", True, "Install Kerberos support: pip install 'adaf-attack[kerberos]'."),
        ("textual", True, "Install TUI support: pip install 'adaf-attack[tui]'."),
    ):
        try:
            __import__(package)
            checks.append(
                {"id": package, "status": "ok", "value": "installed", "remediation": None}
            )
        except ImportError:
            checks.append(
                {
                    "id": package,
                    "status": "warning" if optional else "error",
                    "value": "missing",
                    "remediation": remediation,
                }
            )
    blocking = next((c for c in checks if c["status"] == "error"), None)
    payload = {
        "ok": blocking is None,
        "version": __version__,
        "checks": checks,
        "next_step": blocking["remediation"]
        if blocking
        else "Run `adaf-attack capability-help` to choose a capability.",
    }
    lines = [
        f"{c['status'].upper():7} {c['id']}: {c['value']}"
        + (f"\n  Next step: {c['remediation']}" if explain and c["remediation"] else "")
        for c in checks
    ]
    _emit(
        ctx,
        payload,
        Panel("\n".join(lines), title="ADAF-ATTACK doctor", subtitle=f"v{__version__}"),
    )
    return

    checks: list[str] = []  # type: ignore[no-redef]  # Unreachable legacy display block.
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
def list_capabilities(ctx: typer.Context) -> None:
    """List registered capabilities."""
    import adaf_attack.capabilities  # noqa: F401
    from adaf_attack.core.registry import capability_registry

    caps = capability_registry.list()
    if not caps:
        _emit(ctx, {"ok": True, "capabilities": [], "count": 0}, "No capabilities registered yet.")
        return

    table = Table(title="Registered Capabilities", show_header=True, header_style="bold")
    table.add_column("ID", style="cyan")
    table.add_column("Category")
    table.add_column("Summary")
    table.add_column("Flags")

    for cap in caps:
        flags = ["[red]DESTRUCTIVE[/red]"] if cap.destructive else []
        table.add_row(cap.id, cap.category, cap.summary, " ".join(flags) or "-")

    _emit(
        ctx,
        {
            "ok": True,
            "capabilities": [_capability_payload(cap) for cap in caps],
            "count": len(caps),
            "next_step": "Run `adaf-attack capability-help <id>` for details.",
        },
        table,
    )


@app.command("paths")
def show_paths(ctx: typer.Context) -> None:
    """Show platform data / workspace paths."""
    table = Table(title="ADAF-ATTACK paths", show_header=True)
    table.add_column("Name")
    table.add_column("Path")
    table.add_row("platform", platform_name())
    table.add_row("data", str(user_data_dir()))
    table.add_row("config", str(user_config_dir()))
    table.add_row("workspace", str(default_workspace_dir()))
    _emit(
        ctx,
        {
            "ok": True,
            "platform": platform_name(),
            "data": str(user_data_dir()),
            "config": str(user_config_dir()),
            "workspace": str(default_workspace_dir()),
        },
        table,
    )


def _capability_payload(cap: Any) -> dict[str, Any]:
    return {
        "id": cap.id,
        "category": cap.category,
        "summary": cap.summary,
        "destructive": cap.destructive,
        "tags": list(cap.tags),
        "required_options": ["--domain", "--dc-ip"],
        "optional_options": ["--username", "--password", "--hashes", "--kerberos", "--workspace"],
        "example": f"adaf-attack run {cap.id} --domain corp.example --dc-ip 10.0.0.10"
        + (" --force" if cap.destructive else ""),
        "next_step": f"Run `adaf-attack plan {cap.id} --domain <domain> --dc-ip <host>` before execution.",
    }


@app.command("capability-help")
def capability_help(
    ctx: typer.Context,
    capability: str | None = typer.Argument(None, help="Capability ID; omit for all capabilities."),
) -> None:
    """Generated capability reference, requirements, risks, and examples."""
    import adaf_attack.capabilities  # noqa: F401
    from adaf_attack.core.registry import capability_registry

    caps = capability_registry.list()
    if capability:
        cap = capability_registry.get(capability)
        if cap is None:
            error = error_for(
                "UNKNOWN_CAPABILITY",
                message=f"Unknown capability: {capability}",
                details={"capability": capability},
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        payload = {"ok": True, "capability": _capability_payload(cap)}
        item = _capability_payload(cap)
        human = Panel(
            "\n".join(
                [
                    item["summary"],
                    f"Risk: {'destructive; --force required' if item['destructive'] else 'network enumeration or offline analysis'}",
                    f"Example: {item['example']}",
                    f"Next step: {item['next_step']}",
                ]
            ),
            title=f"Capability: {cap.id}",
        )
        _emit(ctx, payload, human)
        return
    payload = {
        "ok": True,
        "capabilities": [_capability_payload(cap) for cap in caps],
        "count": len(caps),
        "next_step": "Run `adaf-attack capability-help <id>` for a complete command example.",
    }
    table = Table(title="Capability reference", show_header=True)
    table.add_column("ID")
    table.add_column("Risk")
    table.add_column("Summary")
    for cap in caps:
        table.add_row(cap.id, "destructive" if cap.destructive else "standard", cap.summary)
    _emit(ctx, payload, table)


@app.command("plan")
def plan(
    ctx: typer.Context,
    capability: str = typer.Argument(..., help="Capability ID to preview."),
    domain: str = typer.Option(..., "--domain", "-d"),
    dc_ip: str = typer.Option(..., "--dc-ip"),
    force: bool = typer.Option(
        False, "--force", help="Indicate that execution would be authorized."
    ),
) -> None:
    """Preview the target, effects, and risk of a proposed capability run."""
    import adaf_attack.capabilities  # noqa: F401
    from adaf_attack.core.registry import capability_registry

    cap = capability_registry.get(capability)
    if cap is None:
        error = error_for(
            "UNKNOWN_CAPABILITY",
            message=f"Unknown capability: {capability}",
            details={"capability": capability},
        )
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code)
    risk = "high" if cap.destructive else "moderate"
    requires_force = cap.destructive
    next_step = f"adaf-attack run {cap.id} --domain {domain} --dc-ip {dc_ip}" + (
        " --force" if requires_force else ""
    )
    payload = {
        "ok": True,
        "mode": "preview",
        "capability": _capability_payload(cap),
        "target": {"domain": domain, "dc_ip": dc_ip},
        "risk": {
            "level": risk,
            "network_contact": True,
            "may_modify_target": cap.destructive,
            "force_provided": force,
            "requires_force": requires_force,
        },
        "next_step": next_step,
    }
    human = Panel(
        "\n".join(
            [
                f"Target: {domain} @ {dc_ip}",
                f"Risk: {risk}; {'may modify target state' if cap.destructive else 'performs network/offline analysis only'}",
                f"--force: {'provided' if force else 'not provided'}",
                f"Next step: {next_step}",
            ]
        ),
        title=f"Plan preview: {cap.id}",
    )
    _emit(ctx, payload, human)


@app.command("sessions")
def sessions(
    ctx: typer.Context,
    workspace: Path | None = typer.Option(None, "--workspace"),
    session_id: str | None = typer.Option(
        None, "--session", help="Show one session's metadata and event status."
    ),
) -> None:
    """Navigate persisted sessions and report cleanup status (read-only)."""
    root = workspace or default_workspace_dir()
    entries: list[dict[str, Any]] = []
    if root.is_dir():
        for path in sorted((p for p in root.iterdir() if p.is_dir()), reverse=True):
            meta_path = path / "session.json"
            if not meta_path.is_file():
                continue
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                meta = {"session_id": path.name, "metadata_error": True}
            events = path / "events.jsonl"
            entry = {
                "session_id": meta.get("session_id", path.name),
                "created_at": meta.get("created_at"),
                "path": str(path),
                "events_present": events.is_file(),
                "bytes": sum(p.stat().st_size for p in path.rglob("*") if p.is_file()),
            }
            entries.append(entry)
    if session_id:
        entries = [entry for entry in entries if entry["session_id"] == session_id]
    total_bytes = sum(entry["bytes"] for entry in entries)
    payload = {
        "ok": True,
        "workspace": str(root),
        "sessions": entries,
        "cleanup": {
            "action": "read-only status",
            "session_count": len(entries),
            "bytes": total_bytes,
            "next_step": "Review session paths, then remove only explicitly selected sessions outside this command.",
        },
    }
    table = Table(title="Workspace sessions", show_header=True)
    table.add_column("Session")
    table.add_column("Created")
    table.add_column("Events")
    table.add_column("Bytes", justify="right")
    for entry in entries:
        table.add_row(
            entry["session_id"],
            str(entry["created_at"] or "unknown"),
            "yes" if entry["events_present"] else "no",
            str(entry["bytes"]),
        )
    _emit(ctx, payload, table)


@app.command("cleanup")
def cleanup_cmd(ctx: typer.Context, session: Path = typer.Option(..., "--session"), domain: str = typer.Option(..., "--domain", "-d"), dc_ip: str = typer.Option(..., "--dc-ip"), username: str | None = typer.Option(None, "--username", "-u"), password: str | None = typer.Option(None, "--password", "-p"), force: bool = typer.Option(False, "--force")) -> None:
    """Execute recorded session rollbacks; requires explicit force."""
    if not force:
        raise typer.BadParameter("cleanup execution requires --force")
    from adaf_attack.core.cleanup import execute_cleanup
    result = execute_cleanup(session, Target(domain=domain, dc_ip=dc_ip, username=username, password=password))
    _emit(ctx, {"ok": True, **result}, Panel(f"Completed: {result['completed']}", title="Cleanup"))


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
    ctx: typer.Context,
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
        None, "--write-target", help="Approved write target DN/SAM (requires --force)"
    ),
    attribute: str | None = typer.Option(
        None, "--attribute", help="LDAP attribute for an approved identity write"
    ),
    value: str | None = typer.Option(
        None, "--value", help="Approved value for a mutation or lifecycle operation"
    ),
    descriptor_hex: str | None = typer.Option(
        None, "--descriptor-hex", help="Binary security descriptor as hexadecimal"
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
    operation: str | None = typer.Option(None, "--operation", help="Lifecycle helper operation"),
    artifact: str | None = typer.Option(None, "--artifact", help="Lifecycle helper source artifact"),
    impersonate: str | None = typer.Option(None, "--impersonate", help="Approved S4U identity"),
    spn: str | None = typer.Option(None, "--spn", help="Service principal name for a ticket workflow"),
) -> None:
    """Run a capability against a target."""
    target = _build_target(
        domain, dc_ip, username, password, hashes, aes_key, ccache, use_kerberos, ldaps
    )

    if not _json_mode(ctx):
        _console(ctx).print(
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
    if attribute:
        extra["attribute"] = attribute
    if value:
        extra["value"] = value
    if descriptor_hex:
        extra["descriptor_hex"] = descriptor_hex
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
    if operation:
        extra["operation"] = operation
    if artifact:
        extra["artifact"] = artifact
    if impersonate:
        extra["impersonate"] = impersonate
    if spn:
        extra["spn"] = spn

    try:
        out = execute_capability(
            capability,
            target,
            force=force,
            include_secrets=include_secrets,
            workspace=workspace,
            creds_file=creds_file,
            log=None if _json_mode(ctx) else lambda m: _console(ctx).print(m),
            **extra,
        )
        if _json_mode(ctx):
            _emit(ctx, out, "")
            return
        interesting = out.get("interesting") or {}
        top = interesting.get("top_paths") or []
        if top:
            _console(ctx).print("\nTop ranked paths (sample)")
            for ranked_path in top[:5]:
                _console(ctx).print(
                    f"  score={ranked_path['score']:>5}  len={ranked_path['length']}  "
                    + " → ".join(x.split("@")[0] for x in ranked_path["path"][:6])
                )
        if out.get("cred_attempts"):
            _console(ctx).print(f"Cred attempts: {out['cred_attempts']}")
        if out.get("username"):
            _console(ctx).print(f"Using principal: {out['username']} ({out.get('auth')})")
        _console(ctx).print(f"\nSession: {out['session_path']}")
    except RunError as exc:
        text = str(exc)
        code = "RUN_FAILED"
        if text.startswith("Unknown capability:"):
            code = "UNKNOWN_CAPABILITY"
        elif "DESTRUCTIVE" in text and "--force" in text:
            code = "DESTRUCTIVE_CONFIRMATION_REQUIRED"
        elif "no runner implemented" in text:
            code = "CAPABILITY_UNAVAILABLE"
        error = error_for(code, message=text, details={"capability": capability})
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from exc


@engagement_app.command("init")
def engagement_init(
    output: Path = typer.Option(Path("engagement.yaml"), "--output", "-o"),
) -> None:
    """Write a conservative engagement-plan template."""
    if output.exists():
        raise typer.BadParameter(f"Refusing to overwrite existing file: {output}")
    output.write_text(
        """# Complete and review this scope before running.
engagement_id: ENG-YYYY-001
target:
  domain: corp.example
  dc_ip: 10.0.0.10
allowed_targets: [10.0.0.10]
opsec_profile: balanced  # stealth | balanced | loud
allowed_capabilities: [ldap-enum, trusts-enum, adcs-enum, acl-enum, report]
phases:
  - name: discovery
    capabilities: [ldap-enum, trusts-enum, adcs-enum, acl-enum]
  - name: reporting
    capabilities: [report]
""",
        encoding="utf-8",
    )
    typer.echo(f"Wrote {output}")


@engagement_app.command("validate")
def engagement_validate(ctx: typer.Context, plan: Path = typer.Argument(...)) -> None:
    """Validate a plan without contacting a target."""
    from adaf_attack.core.engagement import EngagementError, load_plan

    try:
        value = load_plan(plan)
    except EngagementError as exc:
        error = ActionableError("ENGAGEMENT_PLAN_INVALID", str(exc), "Correct the YAML scope and validate again.")
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from exc
    _emit(ctx, {"ok": True, "engagement_id": value.engagement_id, "target": value.dc_ip, "allowed_capabilities": list(value.allowed_capabilities), "phase_count": len(value.phases)}, Panel(f"{value.engagement_id}\nTarget: {value.domain} @ {value.dc_ip}\nPhases: {len(value.phases)}", title="Engagement plan valid"))


@engagement_app.command("run")
def engagement_run(
    ctx: typer.Context,
    plan: Path = typer.Argument(...),
    workspace: Path = typer.Option(Path("workspaces"), "--workspace"),
    username: str | None = typer.Option(None, "--username", "-u"),
    password: str | None = typer.Option(None, "--password", "-p"),
    approval_token: str | None = typer.Option(None, "--approval-token", envvar="ADAF_APPROVAL_TOKEN"),
) -> None:
    """Execute only the capabilities authorized by a validated engagement plan."""
    from adaf_attack.core.engagement import EngagementError, load_plan, run_engagement

    try:
        result = run_engagement(load_plan(plan), workspace=workspace, username=username, password=password, approval_token=approval_token)
    except EngagementError as exc:
        error = ActionableError("ENGAGEMENT_RUN_BLOCKED", str(exc), "Review target scope, authorization, and phase configuration.")
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from exc
    _emit(ctx, {"ok": True, **result}, Panel(f"Engagement: {result['engagement_id']}\nCapabilities: {len(result['capabilities'])}\nFindings: {result['finding_count']}\nSession: {result['session_path']}", title="Engagement complete"))


@engagement_app.command("report")
def engagement_report(ctx: typer.Context, session: Path = typer.Option(..., "--session"), engagement_id: str = typer.Option("unassigned", "--engagement-id")) -> None:
    """Generate executive, technical, and remediation HTML/PDF reports from evidence."""
    from adaf_attack.core.reporting import generate_report_bundle

    if not session.is_dir():
        error = ActionableError("SESSION_NOT_FOUND", "The session directory does not exist.", "Pass a completed engagement session with --session.")
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code)
    result = generate_report_bundle(session, engagement_id=engagement_id)
    _emit(ctx, {"ok": True, **result}, Panel(f"Findings: {result['finding_count']}\nReport directory: {session / 'reports'}", title="Client report bundle"))


@engagement_app.command("package")
def engagement_package(
    ctx: typer.Context,
    session: Path = typer.Option(..., "--session"),
    output: Path = typer.Option(Path("engagement-package.zip"), "--output", "-o"),
    profile: str = typer.Option("client", "--profile", help="operator, purple, or client"),
) -> None:
    """Create a redacted evidence archive without including the session vault."""
    from adaf_attack.core.control_plane import package_evidence

    try:
        result = package_evidence(session, output, profile=profile)
    except ValueError as exc:
        error = ActionableError("ENGAGEMENT_PACKAGE_FAILED", str(exc), "Use an existing session and redaction profile.")
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from exc
    _emit(ctx, {"ok": True, **result}, Panel(f"Archive: {result['archive']}\nFiles: {result['file_count']}\nProfile: {result['profile']}", title="Engagement evidence package"))


@app.command("rank-paths")
def rank_paths_cmd(
    ctx: typer.Context,
    graph: Path = typer.Option(..., "--graph", "-g", help="Path to graph.json"),
    start: str | None = typer.Option(None, "--start", "-s", help="Start principal (SAM or id)"),
    max_depth: int = typer.Option(6, "--max-depth"),
    limit: int = typer.Option(25, "--limit"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write ranked JSON here"),
) -> None:
    """Rank attack paths from a saved graph.json (offline, no DC contact)."""
    if not graph.is_file():
        error = error_for("GRAPH_NOT_FOUND", details={"graph": str(graph)})
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code)

    g = AttackGraph.from_file(graph)
    if not _json_mode(ctx):
        _console(ctx).print(
            f"Loaded {g.summary()['nodes']} nodes / {g.summary()['edges']} edges from {graph}"
        )

    starts = [start] if start else None
    ranked = g.rank_from_principals(starts, max_depth=max_depth, limit=limit)
    exploit_chains = g.rank_exploit_chains(starts, max_depth=max_depth, limit=limit)

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

    payload = {
        "graph": str(graph),
        "start": start,
        "paths": ranked,
        "count": len(ranked),
        "exploit_chains": exploit_chains,
        "exploit_chain_count": len(exploit_chains),
    }
    if output:
        output.write_text(__import__("json").dumps(payload, indent=2) + "\n", encoding="utf-8")
        payload["output"] = str(output)
    if _json_mode(ctx):
        _emit(ctx, {"ok": True, **payload}, "")
    elif ranked or exploit_chains:
        if ranked:
            _console(ctx).print(table)
        if exploit_chains:
            _console(ctx).print("\nExploit chains (evidence-backed)")
            for chain in exploit_chains[:10]:
                _console(ctx).print(
                    f"  score={chain['score']:>5}  {chain['terminal_relation']}: "
                    f"{chain['impact']} ({chain['confidence']} confidence)"
                )
        if output:
            _console(ctx).print(f"Wrote {output}")
    else:
        _console(ctx).print("No paths found")


def _offline_sessions(values: list[Path]) -> list[Path]:
    missing = [str(path) for path in values if not path.is_dir()]
    if missing:
        raise ActionableError(
            "SESSION_NOT_FOUND",
            "One or more session directories do not exist.",
            "Pass an existing session directory created by a prior authorized run.",
            details={"missing": missing},
        )
    return values


@app.command("credential-exposure")
def credential_exposure_cmd(
    ctx: typer.Context,
    session: list[Path] = typer.Option(
        ..., "--session", help="Session directory; repeat to correlate."
    ),
) -> None:
    """Prioritize credential-exposure evidence without disclosing secret values."""
    from adaf_attack.core.workflows import credential_exposure

    try:
        payload = credential_exposure(_offline_sessions(session))
    except ActionableError as error:
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from error
    _emit(
        ctx,
        {"ok": True, **payload},
        Panel(
            f"Exposure artifacts: {payload['count']}\nNext step: {payload['next_step']}",
            title="Credential exposure correlation",
        ),
    )


@app.command("bloodhound-reconcile")
def bloodhound_reconcile_cmd(
    ctx: typer.Context,
    session: Path = typer.Option(..., "--session"),
    bloodhound: Path = typer.Option(..., "--bloodhound"),
) -> None:
    """Reconcile a saved session graph with a BloodHound JSON export."""
    from adaf_attack.core.workflows import bloodhound_reconcile

    try:
        _offline_sessions([session])
        if not bloodhound.is_file():
            raise ActionableError(
                "BLOODHOUND_FILE_NOT_FOUND",
                "The BloodHound JSON file does not exist.",
                "Pass a valid JSON export with --bloodhound.",
            )
        payload = bloodhound_reconcile(session, bloodhound)
    except ActionableError as error:
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from error
    _emit(
        ctx,
        {"ok": True, **payload},
        Panel(
            f"Only local: {len(payload['only_local'])}\nOnly BloodHound: {len(payload['only_bloodhound'])}\nNext step: {payload['next_step']}",
            title="BloodHound reconciliation",
        ),
    )


@app.command("trust-correlation")
def trust_correlation_cmd(
    ctx: typer.Context, session: list[Path] = typer.Option(..., "--session")
) -> None:
    """Correlate trust artifacts and cross-forest graph evidence."""
    from adaf_attack.core.workflows import correlate_trusts

    try:
        payload = correlate_trusts(_offline_sessions(session))
    except ActionableError as error:
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from error
    _emit(
        ctx,
        {"ok": True, **payload},
        Panel(
            f"Sessions correlated: {len(payload['records'])}\nNext step: {payload['next_step']}",
            title="Trust and identity correlation",
        ),
    )


def _surface_command(ctx: typer.Context, session: Path, kind: str, title: str) -> None:
    from adaf_attack.core.workflows import validate_surface

    try:
        _offline_sessions([session])
        payload = validate_surface(session, kind)
    except ActionableError as error:
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from error
    _emit(
        ctx,
        {"ok": True, **payload},
        Panel(
            f"Validated: {'yes' if payload['validated'] else 'no evidence found'}\nNext step: {payload['next_step']}",
            title=title,
        ),
    )


@app.command("delegation-validation")
def delegation_validation_cmd(
    ctx: typer.Context, session: Path = typer.Option(..., "--session")
) -> None:
    """Validate delegation/RBCD evidence from an authorized session."""
    _surface_command(ctx, session, "delegation", "Delegation path validation")


@app.command("adcs-validation")
def adcs_validation_cmd(ctx: typer.Context, session: Path = typer.Option(..., "--session")) -> None:
    """Validate AD CS attack-path evidence without requesting certificates."""
    _surface_command(ctx, session, "adcs", "AD CS attack-path validation")


@app.command("campaign-compose")
def campaign_compose_cmd(
    ctx: typer.Context, session: list[Path] = typer.Option(..., "--session")
) -> None:
    """Compose a read-only multi-session attack-path campaign."""
    from adaf_attack.core.workflows import compose_campaign

    try:
        payload = compose_campaign(_offline_sessions(session))
    except ActionableError as error:
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from error
    _emit(
        ctx,
        {"ok": True, **payload},
        Panel(
            f"Campaign phases: {len(payload['phases'])}\nNext step: {payload['next_step']}",
            title="Multi-session campaign composer",
        ),
    )


@app.command("forest-campaign")
def forest_campaign_cmd(ctx: typer.Context, session: list[Path] = typer.Option(..., "--session")) -> None:
    """Compose a forest-aware, read-only campaign from completed sessions."""
    from adaf_attack.core.forest_campaign import compose_forest_campaign

    try:
        payload = compose_forest_campaign(_offline_sessions(session))
    except (ActionableError, ValueError) as exc:
        error = ActionableError("FOREST_CAMPAIGN_FAILED", str(exc), "Pass completed, authorized session directories.")
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from exc
    _emit(ctx, {"ok": True, **payload}, Panel(f"Domains: {len(payload['domains'])}\nTrust transitions: {len(payload['trust_transitions'])}", title="Forest-aware campaign"))


@app.command("purple-handoff")
def purple_handoff_cmd(ctx: typer.Context, session: Path = typer.Option(..., "--session")) -> None:
    """Build a detection-aware handoff from recorded evidence."""
    from adaf_attack.core.workflows import purple_handoff

    try:
        _offline_sessions([session])
        payload = purple_handoff(session)
    except ActionableError as error:
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from error
    _emit(
        ctx,
        {"ok": True, **payload},
        Panel(
            f"Detection hypotheses: {len(payload['detections'])}\nNext step: {payload['next_step']}",
            title="Purple-team handoff",
        ),
    )


@app.command("gpo-impact-plan")
def gpo_impact_plan_cmd(ctx: typer.Context, session: Path = typer.Option(..., "--session")) -> None:
    """Plan controlled GPO impact validation from saved evidence."""
    _surface_command(ctx, session, "gpo", "GPO impact planner")


@app.command("coercion-fixtures")
def coercion_fixtures_cmd(
    ctx: typer.Context,
    fixtures: Path = typer.Option(..., "--fixtures"),
    authorized_fixtures: bool = typer.Option(
        False, "--authorized-fixtures", help="Confirm fixtures are isolated and authorized."
    ),
) -> None:
    """Validate authorized coercion-detection fixtures; never contacts a target."""
    from adaf_attack.core.workflows import validate_fixtures

    if not authorized_fixtures:
        error = ActionableError(
            "FIXTURE_AUTHORIZATION_REQUIRED",
            "Fixture validation requires explicit confirmation that fixtures are authorized.",
            "Re-run with --authorized-fixtures only for isolated, authorized test data.",
        )
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code)
    if not fixtures.is_dir():
        error = ActionableError(
            "FIXTURE_DIRECTORY_NOT_FOUND",
            "The fixture directory does not exist.",
            "Pass an existing directory containing JSON fixtures.",
        )
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code)
    payload = validate_fixtures(fixtures)
    _emit(
        ctx,
        {"ok": payload["valid"], **payload},
        Panel(
            f"Fixtures: {len(payload['fixtures'])}\nValid: {'yes' if payload['valid'] else 'no'}\nNext step: {payload['next_step']}",
            title="Coercion fixture validation",
        ),
    )


@app.command("workflow-profiles")
def workflow_profiles_cmd(
    ctx: typer.Context,
    profile: str | None = typer.Argument(
        None, help="Profile name; omit to list available profiles."
    ),
) -> None:
    """Show repeatable, non-executing operator workflow profiles."""
    from adaf_attack.core.workflows import PROFILES

    if profile and profile not in PROFILES:
        error = ActionableError(
            "UNKNOWN_WORKFLOW_PROFILE",
            f"Unknown workflow profile: {profile}",
            "Run `adaf-attack workflow-profiles` to list valid profile names.",
        )
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code)
    selected = {profile: PROFILES[profile]} if profile else PROFILES
    payload = {
        "ok": True,
        "profiles": selected,
        "next_step": "Select a profile and execute only engagement-authorized steps.",
    }
    _emit(
        ctx,
        payload,
        Panel(
            "\n".join(f"{name}: {item['description']}" for name, item in selected.items()),
            title="Operator workflow profiles",
        ),
    )


@app.command("start")
def start(ctx: typer.Context) -> None:
    """Launch the interactive Textual TUI shell."""
    if ctx.ensure_object(dict).get("non_interactive"):
        error = ActionableError(
            "INTERACTIVE_MODE_DISABLED",
            "The Textual shell cannot run in non-interactive mode.",
            "Use a non-interactive command such as `adaf-attack capability-help` or `adaf-attack plan`.",
        )
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code)
    try:
        from adaf_attack.tui.app import run_tui
    except ImportError as exc:
        error = ActionableError(
            "TUI_DEPENDENCY_MISSING",
            "Textual is required for the interactive shell.",
            "Install TUI support: pip install 'adaf-attack[tui]'.",
        )
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from exc

    run_tui()


if __name__ == "__main__":
    app()
