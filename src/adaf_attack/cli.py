"""Main CLI entrypoint for ADAF-ATTACK."""

from __future__ import annotations

import difflib
import json
import os
import platform as host_platform
import shutil
import socket
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any

import typer
from rich.console import Console, ConsoleRenderable
from rich.markup import escape
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from adaf_attack import __version__
from adaf_attack.cli_product_commands import register_product_commands
from adaf_attack.cli_tool_commands import register_tool_commands
from adaf_attack.cli_ux_commands import register_ux_commands
from adaf_attack.cli_workflow_commands import register_workflow_commands
from adaf_attack.core.auth import describe_auth
from adaf_attack.core.capability_help_data import capability_option_spec
from adaf_attack.core.cli_contract import (
    ERROR_CATALOG,
    ActionableError,
    classify_run_error,
    error_for,
)
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


def _closest_capabilities(value: str, limit: int = 3) -> list[str]:
    """Return useful typo suggestions without guessing at execution."""
    import adaf_attack.capabilities  # noqa: F401
    from adaf_attack.core.registry import capability_registry

    return difflib.get_close_matches(value, capability_registry.ids(), n=limit, cutoff=0.60)


def _unknown_capability_error(value: str) -> ActionableError:
    suggestions = _closest_capabilities(value)
    hint = "Run `adaf-attack capability-help` to see supported capability IDs."
    if suggestions:
        hint = "Did you mean: " + ", ".join(f"`{item}`" for item in suggestions) + "?"
    return ActionableError(
        "UNKNOWN_CAPABILITY",
        f"Unknown capability: {value}",
        hint,
        details={"capability": value, "suggestions": suggestions},
        suggested_command=(
            f"adaf-attack plan {suggestions[0]}" if suggestions else "adaf-attack capability-help"
        ),
    )


def _destructive_ack_path(root: Path) -> Path:
    return root.expanduser().resolve() / ".adaf-attack-destructive-ack.json"


def _require_destructive_ack(
    ctx: typer.Context,
    capability: str,
    root: Path,
    *,
    explicit: bool,
    interactive: bool,
) -> None:
    """Require a one-time, workspace-local acknowledgement for destructive use."""
    marker = _destructive_ack_path(root)
    try:
        acknowledged = json.loads(marker.read_text(encoding="utf-8")) if marker.is_file() else {}
    except (OSError, json.JSONDecodeError):
        acknowledged = {}
    if capability in acknowledged.get("capabilities", []):
        return
    if not explicit:
        if not interactive:
            error = ActionableError(
                "FIRST_DESTRUCTIVE_USE_CONFIRMATION_REQUIRED",
                f"First destructive use of '{capability}' in this workspace requires acknowledgement.",
                f"Run `adaf-attack plan {capability} ...` first, then re-run with --i-understand.",
                suggested_command=f"adaf-attack plan {capability} --domain <domain> --dc-ip <dc>",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        answer = typer.prompt(
            f"Type the capability name '{capability}' to confirm first destructive use",
            default="",
            show_default=False,
        )
        if answer.strip() != capability:
            error = error_for(
                "USER_ABORTED", message="Destructive capability name was not confirmed."
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        acknowledged.setdefault("capabilities", [])
        if capability not in acknowledged["capabilities"]:  # pragma: no branch
            acknowledged["capabilities"].append(capability)
        marker.write_text(json.dumps(acknowledged, indent=2) + "\n", encoding="utf-8")
    except OSError:
        # The acknowledgement still protects this invocation. A read-only
        # workspace must not turn an already explicit approval into a crash.
        if not _json_mode(ctx):
            _console(ctx).print(
                "[yellow]Could not persist the workspace acknowledgement; it will be requested again next time.[/yellow]"
            )


def _why_text(cap: Any) -> str:
    network = (
        "contacts the authorized target over the network"
        if cap.category not in {"analysis", "export"}
        else "does not contact a target"
    )
    mutation = (
        "It may modify target state when write options are used."
        if cap.destructive
        else "It is read-only with respect to target state."
    )
    evidence = f"Evidence is written to the session as {cap.id}.json plus the session event log."
    return f"{cap.summary}. This command {network}. {mutation} {evidence}"


def _workspace_is_empty(root: Path) -> bool:
    if not root.is_dir():
        return True
    for entry in root.iterdir():
        if entry.is_dir() and (entry / "session.json").is_file():
            return False
    return True


def _humanize_bytes(n: int) -> str:
    step = 1024.0
    for unit in ("B", "KB", "MB", "GB"):
        if n < step:
            return f"{int(n)} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n = int(n / step)
    return f"{n:.1f} TB"


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
        ) from exc
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _delta(seconds: int) -> timedelta:
    return timedelta(seconds=seconds)


def _path_status(path: Path) -> tuple[bool, bool]:
    exists = path.exists()
    if exists:
        return True, os.access(path, os.W_OK)
    parent = path.parent
    return False, parent.exists() and os.access(parent, os.W_OK)


def _path_write_probe(path: Path) -> tuple[bool, str | None]:
    """Create and remove a harmless probe file so doctor tests real write access."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix=".adaf-attack-write-test-", dir=path):
            pass
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return True, None


def _path_check(path_id: str, path: Path) -> dict[str, Any]:
    writable, error = _path_write_probe(path)
    remediation = None
    if not writable:
        env_hint = {
            "data_dir": " Set ADAF_ATTACK_DATA_DIR to a writable directory for application data.",
            "config_dir": " Set ADAF_ATTACK_CONFIG_DIR to a writable directory for user configuration.",
            "workspace": " Set ADAF_ATTACK_WORKSPACE to a writable directory for the workspace.",
        }.get(path_id, " Check the directory permissions.")
        remediation = (
            f"Cannot write {path_id} directory {path}. Run `adaf-attack paths --repair` "
            f"to create missing directories.{env_hint} Then rerun "
            "`adaf-attack doctor --profile user-readiness`."
        )
    return {
        "id": path_id,
        "status": "ok" if writable else "error",
        "severity": "advisory" if writable else "blocking",
        "scope": "offline",
        "value": str(path) if error is None else f"{path} ({error})",
        "remediation": remediation,
    }


app = typer.Typer(
    name="adaf-attack",
    help="Aggressive Active Directory offensive toolkit for senior internal red teamers.",
    no_args_is_help=True,
    invoke_without_command=True,
    rich_markup_mode="rich",
    suggest_commands=True,
)
engagement_app = typer.Typer(help="Scoped engagement plans, execution, and report bundles.")
app.add_typer(engagement_app, name="engagement")
ad_recon_app = typer.Typer(help="First-class, read-only Active Directory reconnaissance.")
app.add_typer(ad_recon_app, name="ad-recon")


def _console(ctx: typer.Context) -> Console:
    config = ctx.ensure_object(dict)
    return Console(no_color=config.get("no_color", False), highlight=False)


def _json_mode(ctx: typer.Context) -> bool:
    return ctx.ensure_object(dict).get("output_format") == "json"


def _output_format(ctx: typer.Context) -> str:
    return str(ctx.ensure_object(dict).get("output_format") or "human")


def _summary_lines(payload: dict[str, Any]) -> list[str]:
    lines = [f"ok: {payload.get('ok')}"]
    for key in ("count", "stage", "mode", "session_path", "command", "next_step"):
        if payload.get(key) is not None:
            lines.append(f"{key}: {payload[key]}")
    capability = payload.get("capability")
    if isinstance(capability, dict):
        lines.append(f"capability: {capability.get('id')}")
        if capability.get("summary"):
            lines.append(f"summary: {capability['summary']}")
    if payload.get("next_steps"):
        lines.append("next_steps:")
        lines.extend(f"- {step}" for step in payload["next_steps"])
    return lines


def _beginner_lines(payload: dict[str, Any]) -> list[str]:
    if isinstance(payload.get("actions"), list):
        return [
            f"{item.get('goal')}: {item.get('command')}"
            for item in payload["actions"]
            if isinstance(item, dict)
        ]
    capability = payload.get("capability")
    if isinstance(capability, dict):
        difficulty = capability.get("difficulty") or {}
        return [
            f"{capability.get('id')}: {capability.get('summary')}",
            f"Difficulty: {difficulty.get('level', 'unknown')}",
            f"Example: {capability.get('example')}",
            f"Next: {capability.get('next_step')}",
        ]
    finding = payload.get("finding")
    if isinstance(finding, dict):
        return [
            f"{finding.get('title')} is rated {finding.get('severity')}.",
            str(finding.get("why_it_matters")),
            f"Next: {finding.get('recommended_next_step')}",
        ]
    return _summary_lines(payload)


def _emit(ctx: typer.Context, payload: dict[str, Any], human: Any) -> None:
    if _json_mode(ctx):
        typer.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))
    elif _output_format(ctx) == "summary":
        _console(ctx).print("\n".join(_summary_lines(payload)))
    elif _output_format(ctx) == "beginner":
        _console(ctx).print(Panel("\n".join(_beginner_lines(payload)), title="Beginner summary"))
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
    output_format: str = typer.Option(
        "human", "--format", help="Output format: human, json, summary, table, or beginner."
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable terminal color and styling."),
    non_interactive: bool = typer.Option(
        False, "--non-interactive", help="Never prompt; suitable for scripts and CI."
    ),
) -> None:
    if output_format not in {"human", "json", "summary", "table", "beginner"}:
        raise typer.BadParameter(
            "must be 'human', 'json', 'summary', 'table', or 'beginner'",
            param_hint="--format",
        )
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


_MIN_PYTHON = (3, 11)
_MAX_PYTHON = (3, 15)

# Importable packages doctor probes. `optional` packages degrade a subset of
# capabilities when missing (warning); required packages block everything.
_MODULE_CHECKS: tuple[tuple[str, bool, str], ...] = (
    (
        "typer",
        False,
        "Repair the installation in the active environment: python -m pip install --force-reinstall 'adaf-attack'.",
    ),
    (
        "rich",
        False,
        "Repair the installation in the active environment: python -m pip install --force-reinstall 'adaf-attack'.",
    ),
    (
        "pydantic",
        False,
        "Repair the installation in the active environment: python -m pip install --force-reinstall 'adaf-attack'.",
    ),
    (
        "pydantic_settings",
        False,
        "Repair the installation in the active environment: python -m pip install --force-reinstall 'adaf-attack'.",
    ),
    (
        "httpx",
        False,
        "Repair the installation in the active environment: python -m pip install --force-reinstall 'adaf-attack'.",
    ),
    ("ldap3", False, "Install the base package dependencies: pip install -e ."),
    (
        "yaml",
        False,
        "Repair the installation in the active environment: python -m pip install --force-reinstall 'adaf-attack'.",
    ),
    (
        "cryptography",
        False,
        "Repair the installation in the active environment: python -m pip install --force-reinstall 'adaf-attack'.",
    ),
    ("impacket", True, "Install Kerberos support: pip install 'adaf-attack[kerberos]'."),
    ("textual", True, "Install TUI support: pip install 'adaf-attack[tui]'."),
    ("reportlab", True, "Install PDF reporting support: pip install 'adaf-attack[reports]'."),
    ("pypdf", True, "Install PDF reporting support: pip install 'adaf-attack[reports]'."),
)

_MODULE_DISTRIBUTIONS = {
    "pydantic_settings": "pydantic-settings",
    "yaml": "PyYAML",
}

# External CLI tools capabilities shell out to. Each entry lists the candidate
# executable names to resolve on PATH, matching the capability's own lookup.
_BINARY_CHECKS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    (
        "ntlmrelayx",
        ("impacket-ntlmrelayx", "ntlmrelayx.py"),
        "Install Kerberos support so ntlmrelayx is on PATH: pip install 'adaf-attack[kerberos]'.",
    ),
    (
        "certipy",
        ("certipy",),
        "Install AD CS tooling so certipy is on PATH: pip install 'adaf-attack[certipy]'.",
    ),
)


def _python_supported() -> bool:
    return _MIN_PYTHON <= sys.version_info < _MAX_PYTHON


def _resolve_binary(candidates: tuple[str, ...]) -> str | None:
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


_DOCTOR_PROFILES = {
    "offline": "Base installation and safe local workflows; no network probes.",
    "user-readiness": "Fresh-user installation, packaged demo, and safe local workflows; no network probes.",
    "operator": "Full operator extras, reporting, and Kerberos tooling; no network probes.",
    "certipy": "AD CS tooling boundary; no network probes.",
    "live-ad": "Target preflight for DNS and common AD ports; requires explicit target arguments.",
}


def _doctor_check(
    check_id: str,
    status: str,
    value: Any,
    remediation: str | None = None,
    *,
    scope: str = "offline",
    severity: str | None = None,
) -> dict[str, Any]:
    return {
        "id": check_id,
        "status": status,
        "severity": severity or ("blocking" if status == "error" else "advisory"),
        "scope": scope,
        "value": value,
        "remediation": remediation,
    }


def _package_version(name: str) -> str | None:
    try:
        return importlib_metadata.version(name)
    except importlib_metadata.PackageNotFoundError:
        return None


def _installation_kind() -> str:
    try:
        distribution = importlib_metadata.distribution("adaf-attack")
        direct_url = distribution.read_text("direct_url.json")
    except (importlib_metadata.PackageNotFoundError, OSError):
        return "unknown"
    if direct_url and '"editable": true' in direct_url:
        return "editable"
    if direct_url and '"dir_info"' in direct_url:
        return "source"
    return "wheel-or-sdist"


def _socket_check(host: str, port: int, timeout: float) -> tuple[str, str | None]:
    try:
        socket.create_connection((host, port), timeout=timeout).close()
    except socket.gaierror as exc:
        return "error", f"DNS resolution failed for {host}: {exc}"
    except OSError as exc:
        return "warning", f"{host}:{port} is not reachable: {type(exc).__name__}: {exc}"
    return "ok", None


def _doctor_payload(
    profile: str,
    *,
    domain: str | None = None,
    dc_ip: str | None = None,
    timeout: float = 3.0,
) -> dict[str, Any]:
    if profile not in _DOCTOR_PROFILES:
        raise typer.BadParameter(
            f"unknown doctor profile {profile!r}; choose from {', '.join(_DOCTOR_PROFILES)}",
            param_hint="--profile",
        )
    if timeout <= 0 or timeout > 60:
        raise typer.BadParameter("must be between 0 and 60 seconds", param_hint="--timeout")

    python_ok = _python_supported()
    checks: list[dict[str, Any]] = [
        _doctor_check("platform", "ok", platform_name()),
        _doctor_check("architecture", "ok", host_platform.machine() or "unknown"),
        _doctor_check("os-release", "ok", f"{host_platform.system()} {host_platform.release()}"),
        _doctor_check(
            "python",
            "ok" if python_ok else "error",
            sys.version.split()[0],
            None
            if python_ok
            else "Use Python 3.11, 3.12, 3.13, or 3.14 (see the supported-platform guide).",
        ),
        _doctor_check("python-executable", "ok", str(Path(sys.executable).resolve())),
        _doctor_check(
            "virtual-environment",
            "ok" if sys.prefix != sys.base_prefix else "warning",
            "active" if sys.prefix != sys.base_prefix else "not active",
            None
            if sys.prefix != sys.base_prefix
            else "Create and activate an isolated venv before installing: python -m venv .venv.",
        ),
        _doctor_check(
            "pip",
            "ok" if _package_version("pip") else "warning",
            _package_version("pip") or "not found",
        ),
        _doctor_check("installation", "ok", _installation_kind()),
        _path_check("data_dir", user_data_dir()),
        _path_check("config_dir", user_config_dir()),
        _path_check("workspace", default_workspace_dir()),
    ]

    for check in checks:
        if check["id"] in {"data_dir", "config_dir", "workspace"}:
            check["scope"] = "offline"
            # Offline and demo profiles must remain usable on read-only hosts
            # (for example a packaged checkout or support container). Keep the
            # probe result visible, but do not make it block read-only checks;
            # commands that actually write still report their own actionable
            # error at the write boundary.
            if profile in {"offline", "user-readiness"} and check["status"] == "error":
                check["status"] = "warning"
                check["severity"] = "advisory"

    for package, optional, remediation in _MODULE_CHECKS:
        try:
            module = __import__(package)
            distribution = _MODULE_DISTRIBUTIONS.get(package, package)
            checks.append(
                _doctor_check(package, "ok", _package_version(distribution) or "installed")
            )
            del module
        except ImportError:
            checks.append(
                _doctor_check(
                    package,
                    "warning" if optional else "error",
                    "missing",
                    remediation,
                    severity="advisory" if optional else "blocking",
                )
            )

    if profile == "user-readiness":
        try:
            from importlib.resources import files

            demo_files = files("adaf_attack.demo_data")
            missing = [
                name
                for name in ("acl-enum.json", "adcs-enum.json")
                if not demo_files.joinpath(name).is_file()
            ]
        except (ImportError, ModuleNotFoundError, OSError) as exc:
            missing = [str(exc)]
        checks.append(
            _doctor_check(
                "packaged-demo",
                "ok" if not missing else "error",
                "available" if not missing else ", ".join(missing),
                None
                if not missing
                else "Reinstall the release artifact; packaged demo fixtures are missing.",
                scope="user-readiness",
            )
        )

    required_packages: set[str] = set()
    if profile == "operator":
        required_packages.add("impacket")
    if profile == "operator":
        required_packages.update({"textual", "reportlab", "pypdf"})
    if profile == "certipy":
        required_packages.add("certipy")
        checks.append(
            _doctor_check(
                "certipy",
                "ok" if _package_version("certipy-ad") else "error",
                _package_version("certipy-ad") or "missing",
                None
                if _package_version("certipy-ad")
                else "Install AD CS tooling: pip install 'adaf-attack[certipy]'.",
                scope="certipy",
            )
        )
    for check in checks:
        if check["id"] in required_packages and check["status"] != "ok":
            check["status"] = "error"
            check["severity"] = "blocking"
            check["scope"] = profile

    for check_id, candidates, remediation in _BINARY_CHECKS:
        resolved = _resolve_binary(candidates)
        binary_required = (profile == "operator" and check_id == "ntlmrelayx") or (
            profile == "certipy" and check_id == "certipy"
        )
        checks.append(
            _doctor_check(
                f"{check_id} (cli)",
                "ok" if resolved else ("error" if binary_required else "warning"),
                resolved or "not found",
                None if resolved else remediation,
                scope=profile if binary_required else "offline",
                severity="blocking" if binary_required and not resolved else "advisory",
            )
        )

    if profile == "live-ad":
        if not domain or not dc_ip:
            checks.append(
                _doctor_check(
                    "target-arguments",
                    "error",
                    "domain and dc-ip are required",
                    "Pass --domain <authorized-domain> and --dc-ip <authorized-dc> to run live-AD preflight.",
                    scope="live-ad",
                )
            )
        else:
            try:
                addresses = sorted({item[4][0] for item in socket.getaddrinfo(domain, None)})
                checks.append(
                    _doctor_check(
                        "domain-dns",
                        "ok",
                        {"host": domain, "addresses": addresses},
                        scope="live-ad",
                    )
                )
            except (OSError, socket.gaierror) as exc:
                checks.append(
                    _doctor_check(
                        "domain-dns",
                        "error",
                        f"{domain}: {type(exc).__name__}: {exc}",
                        "Configure DNS for the authorized domain or use the lab DNS server, then rerun doctor.",
                        scope="live-ad",
                    )
                )
            for port, service in ((53, "dns"), (88, "kerberos"), (389, "ldap"), (445, "smb")):
                status, detail = _socket_check(dc_ip, port, timeout)
                checks.append(
                    _doctor_check(
                        f"dc-{service}",
                        status,
                        f"{dc_ip}:{port}" if status == "ok" else detail,
                        None
                        if status == "ok"
                        else f"Verify the authorized DC address, firewall, and lab network for {service} ({dc_ip}:{port}).",
                        scope="live-ad",
                        severity="advisory" if status == "warning" else None,
                    )
                )

    blocking = next((check for check in checks if check["status"] == "error"), None)
    blocking_checks = [check["id"] for check in checks if check["status"] == "error"]
    advisory_checks = [check["id"] for check in checks if check["status"] == "warning"]
    first_run = _workspace_is_empty(default_workspace_dir())
    if blocking:
        next_step = blocking["remediation"]
    elif profile == "live-ad":
        next_step = (
            "Run `adaf-attack plan ldap-enum --domain <domain> --dc-ip <dc>` before connecting."
        )
    elif first_run:
        next_step = (
            "First run detected. Try `adaf-attack quickstart` for a safe, offline demo, "
            "then run `adaf-attack list-capabilities --novice`. When you are ready for an "
            "authorized engagement, use `adaf-attack engagement init --output engagement.yaml`."
        )
    else:
        next_step = "Run `adaf-attack capability-help` to choose a capability."
    return {
        "ok": blocking is None,
        "profile": profile,
        "profile_description": _DOCTOR_PROFILES[profile],
        "version": __version__,
        "checks": checks,
        "first_run": first_run,
        "next_step": next_step,
        "blocking_checks": blocking_checks,
        "advisory_checks": advisory_checks,
        "readiness": {
            "ready": not blocking_checks,
            "install_verification": "adaf-attack doctor --profile user-readiness --explain",
            "safe_first_run": "adaf-attack quickstart",
            "next_command": "adaf-attack list-capabilities --novice",
        },
    }


@app.command("doctor")
def doctor(
    ctx: typer.Context,
    explain: bool = typer.Option(False, "--explain", help="Include remediation for every check."),
    profile: str = typer.Option(
        "offline",
        "--profile",
        help="Check profile: offline, user-readiness, operator, certipy, or live-ad.",
    ),
    domain: str | None = typer.Option(
        None, "--domain", help="Authorized domain for the live-ad profile."
    ),
    dc_ip: str | None = typer.Option(
        None, "--dc-ip", help="Authorized domain-controller address for live-ad."
    ),
    timeout: float = typer.Option(3.0, "--timeout", help="Per-network-probe timeout in seconds."),
) -> None:
    """Check local prerequisites, or explicitly preflight an authorized AD target."""
    payload = _doctor_payload(profile, domain=domain, dc_ip=dc_ip, timeout=timeout)
    checks = payload["checks"]
    first_run = payload["first_run"]
    glyph = {
        "ok": "[green]OK[/green]",
        "warning": "[yellow]WARN[/yellow]",
        "error": "[red]ERR[/red]",
    }
    lines = [
        f"{glyph.get(c['status'], c['status']):>18} {c['id']}: {escape(str(c['value']))}"
        + (f"\n    Next step: {escape(c['remediation'])}" if explain and c["remediation"] else "")
        for c in checks
    ]
    if first_run:
        lines.append("")
        lines.append("[bold]First run - quickstart:[/bold]")
        for line in payload["next_step"].splitlines()[1:]:
            lines.append(line)
    _emit(
        ctx,
        payload,
        Panel("\n".join(lines), title="ADAF-ATTACK doctor", subtitle=f"v{__version__}"),
    )


@app.command("list-capabilities")
def list_capabilities(
    ctx: typer.Context,
    by_phase: bool = typer.Option(
        False, "--by-phase", help="Group capabilities by kill-chain phase."
    ),
    novice: bool = typer.Option(
        False,
        "--novice",
        help="Beginner view grouped by phase with a GREEN/YELLOW/RED safety tag and Offline column.",
    ),
    safe_only: bool = typer.Option(
        False,
        "--safe-only",
        help="Show only offline-safe (GREEN) capabilities. Useful for a first session.",
    ),
) -> None:
    """List registered capabilities."""
    import adaf_attack.capabilities  # noqa: F401
    from adaf_attack.core.registry import capability_registry

    caps = capability_registry.list()
    if not caps:
        _emit(ctx, {"ok": True, "capabilities": [], "count": 0}, "No capabilities registered yet.")
        return

    from adaf_attack.core.novice import capability_difficulty, safety_summary
    from adaf_attack.core.ux import capability_phase, group_capabilities_by_phase, phase_label

    palette = {"GREEN": "green", "YELLOW": "yellow", "RED": "red"}

    if safe_only:
        caps = [c for c in caps if safety_summary(c)["level"] == "GREEN"]
        if not caps:
            _emit(
                ctx,
                {"ok": True, "capabilities": [], "count": 0, "filter": "safe-only"},
                Panel("No offline-safe capabilities match the current filter.", title="Empty"),
            )
            return

    if novice:
        table = Table(
            title="Capabilities (beginner view)",
            show_header=True,
            header_style="bold",
            caption="GREEN offline-safe · YELLOW reads a live target · RED can modify a target",
        )
        table.add_column("Phase", style="bold")
        table.add_column("ID", style="cyan")
        table.add_column("Safety")
        table.add_column("Difficulty")
        table.add_column("Offline?")
        table.add_column("What it does")
        by_phase_groups = group_capabilities_by_phase()
        if safe_only:
            wanted = {c.id for c in caps}
            by_phase_groups = {
                phase: [cap for cap in group if cap.id in wanted]
                for phase, group in by_phase_groups.items()
            }
        display_caps: list[Any] = []
        current_phase: str | None = None
        for phase, group in by_phase_groups.items():
            if not group:
                continue
            for cap in group:
                safety = safety_summary(cap)
                difficulty = capability_difficulty(cap)
                color = palette.get(str(safety["level"]), "white")
                shown_phase = "" if phase == current_phase else phase_label(phase)
                current_phase = phase
                table.add_row(
                    shown_phase,
                    cap.id,
                    f"[{color}]{safety['level']}[/{color}]",
                    difficulty["level"],
                    "yes" if not safety["network"] else "no",
                    cap.summary,
                )
                display_caps.append(cap)
        _emit(
            ctx,
            {
                "ok": True,
                "view": "novice",
                "safe_only": safe_only,
                "capabilities": [_capability_payload(cap) for cap in display_caps],
                "legend": {
                    "GREEN": "Works from saved evidence and does not contact a target.",
                    "YELLOW": "Reads information from an authorized target and contacts the network.",
                    "RED": "Can change a target when its write options are used.",
                },
                "count": len(display_caps),
                "next_step": (
                    "Start with a GREEN capability, or run "
                    "`adaf-attack run <id> --interactive` for a guided prompt."
                ),
            },
            table,
        )
        return

    table = Table(title="Registered Capabilities", show_header=True, header_style="bold")
    table.add_column("ID", style="cyan")
    if by_phase:
        table.add_column("Phase")
    table.add_column("Category")
    table.add_column("Difficulty")
    table.add_column("Summary")
    table.add_column("Flags")

    display_caps = (
        [cap for group in group_capabilities_by_phase().values() for cap in group]
        if by_phase
        else caps
    )
    for cap in display_caps:
        flags = ["[red]DESTRUCTIVE[/red]"] if cap.destructive else []
        row = [cap.id]
        if by_phase:
            row.append(phase_label(capability_phase(cap)))
        row.extend(
            [
                cap.category,
                capability_difficulty(cap)["level"],
                cap.summary,
                " ".join(flags) or "-",
            ]
        )
        table.add_row(*row)

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
def show_paths(
    ctx: typer.Context,
    repair: bool = typer.Option(
        False,
        "--repair",
        help="Create missing application directories, without deleting or moving data.",
    ),
) -> None:
    """Show paths and optionally create missing per-user directories."""
    entries = [
        ("data", user_data_dir()),
        ("config", user_config_dir()),
        ("workspace", default_workspace_dir()),
    ]
    repairs: list[dict[str, str]] = []
    if repair:
        for name, path in entries:
            try:
                path.mkdir(parents=True, exist_ok=True)
                repairs.append({"name": name, "path": str(path), "status": "created-or-present"})
            except OSError as exc:
                repairs.append({"name": name, "path": str(path), "status": f"error: {exc}"})
    rows = []
    for name, path in entries:
        exists, writable = _path_status(path)
        rows.append(
            {
                "name": name,
                "path": str(path),
                "exists": exists,
                "writable": writable,
            }
        )
    table = Table(title="ADAF-ATTACK paths", show_header=True)
    table.add_column("Name")
    table.add_column("Path")
    table.add_column("Exists")
    table.add_column("Writable")
    table.add_row("platform", platform_name(), "-", "-")
    for row in rows:
        table.add_row(
            str(row["name"]),
            str(row["path"]),
            "[green]yes[/green]" if row["exists"] else "[yellow]no[/yellow]",
            "[green]yes[/green]" if row["writable"] else "[red]no[/red]",
        )
    payload = {
        "ok": not any(item["status"].startswith("error:") for item in repairs),
        "platform": platform_name(),
        "data": str(user_data_dir()),
        "config": str(user_config_dir()),
        "workspace": str(default_workspace_dir()),
        "entries": rows,
        "repair": repairs if repair else None,
        "next_step": (
            "Run `adaf-attack doctor --profile user-readiness` to verify the installation."
            if repair
            else "If a path is not writable, run `adaf-attack paths --repair` or set ADAF_ATTACK_* overrides."
        ),
    }
    if repair:
        table.title = "ADAF-ATTACK paths (repair attempted)"
        table.add_row("next", str(payload["next_step"]), "-", "-")
    _emit(ctx, payload, table)


_SUPPORT_SENSITIVE_KEYS = (
    "password",
    "secret",
    "token",
    "key",
    "credential",
    "username",
    "domain",
    "dc_ip",
    "proxy",
    "certificate",
)


def _sanitize_support_value(value: Any, key: str = "") -> Any:
    lowered = key.lower()
    if any(marker in lowered for marker in _SUPPORT_SENSITIVE_KEYS):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(name): _sanitize_support_value(item, str(name)) for name, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_support_value(item, key) for item in value]
    if isinstance(value, str):
        sanitized = value.replace(str(Path.home()), "<HOME>")
        for username_key in ("USERNAME", "USER", "USERPROFILE"):
            username = os.environ.get(username_key)
            if username:
                sanitized = sanitized.replace(username, "<USER>")
        return sanitized
    return value


def _support_environment() -> dict[str, Any]:
    relevant = {}
    for key in sorted(os.environ):
        if key.startswith(("ADAF_", "XDG_")) or key in {"SHELL", "COMSPEC", "OS"}:
            relevant[key] = {"set": True}
    return relevant


def _replace_support_identifiers(value: Any, identifiers: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        return {key: _replace_support_identifiers(item, identifiers) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_support_identifiers(item, identifiers) for item in value]
    if isinstance(value, str):
        for identifier in identifiers:
            if identifier:
                value = value.replace(identifier, "<TARGET>")
    return value


def _redaction_changes(raw: Any, safe: Any, path: str = "$") -> list[dict[str, str]]:
    """Describe redactions by location/type without exposing the raw value."""
    changes: list[dict[str, str]] = []
    if isinstance(raw, dict) and isinstance(safe, dict):
        for key, value in raw.items():
            child = f"{path}.{key}"
            if key not in safe:
                continue
            if isinstance(value, (dict, list)) and isinstance(safe[key], type(value)):
                changes.extend(_redaction_changes(value, safe[key], child))
            elif value != safe[key]:
                replacement = "<redacted>" if "redact" in str(safe[key]).lower() else "<normalized>"
                changes.append({"path": child, "action": "redacted", "replacement": replacement})
    elif isinstance(raw, list) and isinstance(safe, list):
        for index, (before, after) in enumerate(zip(raw, safe, strict=True)):
            changes.extend(_redaction_changes(before, after, f"{path}[{index}]"))
    return changes


@app.command("support-bundle")
def support_bundle(
    ctx: typer.Context,
    output: Path = typer.Option(Path("adaf-support-bundle.json"), "--output", "-o"),
    profile: str = typer.Option("offline", "--profile", help="Doctor profile to capture."),
    domain: str | None = typer.Option(
        None, "--domain", help="Authorized domain for live-ad preflight."
    ),
    dc_ip: str | None = typer.Option(
        None, "--dc-ip", help="Authorized DC address for live-ad preflight."
    ),
    timeout: float = typer.Option(3.0, "--timeout", help="Per-network-probe timeout in seconds."),
    preview: bool = typer.Option(
        False, "--preview", help="Show what would be redacted without writing or sharing a bundle."
    ),
) -> None:
    """Write a redacted diagnostic bundle safe to attach to support requests."""
    from adaf_attack.core.engineering import diagnostics_snapshot

    payload = _doctor_payload(profile, domain=domain, dc_ip=dc_ip, timeout=timeout)
    raw_doctor = payload
    safe_doctor = _replace_support_identifiers(
        _sanitize_support_value(payload), tuple(item for item in (domain, dc_ip) if item)
    )
    runtime = _sanitize_support_value(
        {
            "python": sys.version.split()[0],
            "executable": str(Path(sys.executable).resolve()),
            "prefix": str(Path(sys.prefix).resolve()),
            "base_prefix": str(Path(sys.base_prefix).resolve()),
            "architecture": host_platform.machine() or "unknown",
            "system": host_platform.system(),
            "release": host_platform.release(),
        }
    )
    bundle = {
        "schema": 1,
        "type": "adaf-attack-support-bundle",
        "generated_at": datetime.now(UTC).isoformat(),
        "version": __version__,
        "runtime": runtime,
        "environment": _support_environment(),
        "doctor": safe_doctor,
        "engineering": diagnostics_snapshot(
            package_version=__version__, workspace=default_workspace_dir()
        ),
    }
    changes = _redaction_changes(raw_doctor, safe_doctor, "$.doctor")
    if preview:
        preview_payload = {
            "ok": True,
            "preview": True,
            "would_write": str(output.expanduser().resolve()),
            "redactions": changes,
            "redaction_count": len(changes),
        }
        _emit(
            ctx,
            preview_payload,
            Panel(
                f"No file written. {len(changes)} field(s) would be redacted or normalized.\n"
                + (
                    "\n".join(f"{item['path']} → {item['replacement']}" for item in changes)
                    or "No redactions detected."
                ),
                title="Support bundle redaction preview",
            ),
        )
        return
    destination = output.expanduser().resolve()
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(bundle, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        error = error_for(
            "SUPPORT_BUNDLE_WRITE_FAILED",
            message=f"Could not write support bundle: {exc}",
            details={"output": str(destination)},
        )
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from exc
    _emit(
        ctx,
        {"ok": True, "output": str(destination), "profile": profile},
        Panel(
            f"Wrote redacted support bundle to {destination}\n"
            "Review it for organization-specific identifiers before sharing.",
            title="ADAF-ATTACK support bundle",
        ),
    )


def _capability_payload(cap: Any) -> dict[str, Any]:
    spec = capability_option_spec(cap.id, cap.destructive)
    example = f"adaf-attack run {cap.id}"
    if "--domain" in spec.required:
        example += " --domain corp.example --dc-ip 10.0.0.10"
    if cap.destructive:
        example += " --force"
    from adaf_attack.core.novice import capability_difficulty
    from adaf_attack.core.ux import (
        capability_prerequisites,
        format_next_actions_block,
        format_stages_progress,
        risk_checklist,
    )

    return {
        "id": cap.id,
        "category": cap.category,
        "summary": cap.summary,
        "destructive": cap.destructive,
        "difficulty": capability_difficulty(cap),
        "tags": list(cap.tags),
        "required_options": list(spec.required),
        "optional_options": list(spec.optional),
        "notes": spec.notes,
        "example": example,
        "preflight_checklist": risk_checklist(cap),
        "stages": format_stages_progress(cap)["stages"],
        "next_step": (
            f"Run `adaf-attack plan {cap.id}"
            + (" --domain <domain> --dc-ip <host>" if "--domain" in spec.required else "")
            + "` before execution."
        ),
        "prerequisites": capability_prerequisites(cap.id),
        "suggested_next": format_next_actions_block(cap)["suggestions"],
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
            error = _unknown_capability_error(capability)
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        from adaf_attack.core.user_config import record_recent_capability

        record_recent_capability(cap.id)
        payload = {"ok": True, "capability": _capability_payload(cap)}
        item = _capability_payload(cap)
        from adaf_attack.core.ux import build_ready_command, risk_checklist

        checklist = risk_checklist(cap)
        ready = build_ready_command(
            cap.id,
            domain="<domain>" if "--domain" in item["required_options"] else None,
            dc_ip="<dc-ip>" if "--dc-ip" in item["required_options"] else None,
            force=cap.destructive,
        )
        required = " ".join(item["required_options"]) or "(none)"
        optional = " ".join(item["optional_options"]) or "(none)"
        lines = [
            item["summary"],
            f"Risk: {'destructive; --force required' if item['destructive'] else 'network enumeration or offline analysis'}",
            f"Required: {required}",
            f"Optional: {optional}",
            "Checklist: "
            + ", ".join(entry["label"] for entry in checklist["items"] if entry["required"]),
            f"Copy-ready: {ready}",
        ]
        if item.get("notes"):
            lines.append(f"Notes: {item['notes']}")
        lines.append(f"Example: {item['example']}")
        lines.append(f"Next step: {item['next_step']}")
        human = Panel("\n".join(lines), title=f"Capability: {cap.id}")
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
    export: Path | None = typer.Option(None, "--export", help="Write the plan as Markdown."),
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
    from adaf_attack.core.ux import build_ready_command, format_stages_progress, risk_checklist

    checklist = risk_checklist(cap)
    stages = format_stages_progress(cap)
    next_step = f"adaf-attack run {cap.id} --domain {domain} --dc-ip {dc_ip}" + (
        " --force" if requires_force else ""
    )
    risk_payload: dict[str, Any] = {
        "level": risk,
        "network_contact": True,
        "may_modify_target": cap.destructive,
        "force_provided": force,
        "requires_force": requires_force,
    }
    payload = {
        "ok": True,
        "mode": "preview",
        "capability": _capability_payload(cap),
        "target": {"domain": domain, "dc_ip": dc_ip},
        "risk": risk_payload,
        "preflight_checklist": checklist,
        "stages": stages,
        "next_step": next_step,
    }
    if export is not None:
        from adaf_attack.core.ux import capability_prerequisites, export_plan_markdown

        export.parent.mkdir(parents=True, exist_ok=True)
        export.write_text(
            export_plan_markdown(
                capability_id=cap.id,
                domain=domain,
                dc_ip=dc_ip,
                risk=risk_payload,
                checklist=checklist,
                ready_command=build_ready_command(
                    cap.id, domain=domain, dc_ip=dc_ip, force=requires_force
                ),
                prerequisites=capability_prerequisites(cap.id),
            ),
            encoding="utf-8",
        )
        payload["export"] = str(export)
    human = Panel(
        "\n".join(
            [
                f"Target: {domain} @ {dc_ip}",
                f"Risk: {risk}; {'may modify target state' if cap.destructive else 'performs network/offline analysis only'}",
                f"--force: {'provided' if force else 'not provided'}",
                f"Opsec: {checklist['opsec_hint']}",
                "Preflight: "
                + ", ".join(item["label"] for item in checklist["items"] if item["required"]),
                "Stages: " + " -> ".join(item["id"] for item in stages["stages"]),
                f"Copy-ready: {build_ready_command(cap.id, domain=domain, dc_ip=dc_ip, force=requires_force)}",
                f"Next step: {next_step}",
            ]
        ),
        title=f"Plan preview: {cap.id}",
    )
    _emit(ctx, payload, human)


@app.command("tour")
def tour(ctx: typer.Context) -> None:
    """Show the guided operator tour."""
    from adaf_attack.core.ux import guided_tour_payload

    payload = guided_tour_payload()
    human = Panel(
        "\n".join(f"{step['title']}: {step['command']}" for step in payload["steps"]),
        title="Operator tour",
    )
    _emit(ctx, {"ok": True, **payload}, human)


@app.command("check")
def check(
    ctx: typer.Context,
    domain: str | None = typer.Option(None, "--domain", "-d"),
    dc_ip: str | None = typer.Option(None, "--dc-ip"),
    timeout: float = typer.Option(3.0, "--timeout"),
) -> None:
    """Check local setup, or preflight an authorized target when both target options are supplied."""
    if bool(domain) != bool(dc_ip):
        raise typer.BadParameter(
            "Provide both --domain and --dc-ip for a target preflight, or neither for setup checks."
        )
    doctor(
        ctx,
        explain=True,
        profile="live-ad" if domain else "user-readiness",
        domain=domain,
        dc_ip=dc_ip,
        timeout=timeout,
    )


@app.command("review")
def review(
    ctx: typer.Context,
    capability: str = typer.Argument(...),
    domain: str = typer.Option(..., "--domain", "-d"),
    dc_ip: str = typer.Option(..., "--dc-ip"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    """Preview a capability before running it."""
    plan(ctx, capability=capability, domain=domain, dc_ip=dc_ip, force=force, export=None)


@app.command("help-me")
def help_me(ctx: typer.Context) -> None:
    """Show the guided tour for new operators."""
    tour(ctx)


@app.command("recent")
def recent(ctx: typer.Context) -> None:
    """Show recently viewed capabilities (stored locally, never targets or credentials)."""
    from adaf_attack.core.registry import capability_registry
    from adaf_attack.core.user_config import recent_capabilities

    items = [capability_registry.get(capability_id) for capability_id in recent_capabilities()]
    capabilities = [cap for cap in items if cap is not None]
    payload = {
        "ok": True,
        "capabilities": [_capability_payload(cap) for cap in capabilities],
        "count": len(capabilities),
        "next_step": "Run `adaf-attack capability-help <id>` to review a recent capability.",
    }
    human = Panel(
        "\n".join(f"{cap.id}: {cap.summary}" for cap in capabilities)
        or "No recent capabilities yet. Browse with `adaf-attack capability-help <id>` or use the TUI.",
        title="Recently viewed capabilities",
    )
    _emit(ctx, payload, human)


favorites_app = typer.Typer(help="Pin frequently used capabilities.")
app.add_typer(favorites_app, name="favorites")


@favorites_app.command("list")
def favorites_list(ctx: typer.Context) -> None:
    """List pinned capabilities."""
    from adaf_attack.core.registry import capability_registry
    from adaf_attack.core.user_config import favorite_capabilities

    ids = favorite_capabilities()
    caps = [capability_registry.get(capability_id) for capability_id in ids]
    resolved = [cap for cap in caps if cap is not None]
    payload = {
        "ok": True,
        "capabilities": [_capability_payload(cap) for cap in resolved],
        "count": len(resolved),
    }
    human = Panel(
        "\n".join(f"{cap.id}: {cap.summary}" for cap in resolved)
        or "No pinned capabilities. Add one with `adaf-attack favorites add <id>`.",
        title="Pinned capabilities",
    )
    _emit(ctx, payload, human)


@favorites_app.command("add")
def favorites_add(ctx: typer.Context, capability: str = typer.Argument(...)) -> None:
    """Pin a capability for quick recall."""
    from adaf_attack.core.registry import capability_registry
    from adaf_attack.core.user_config import set_favorite_capability

    cap = capability_registry.get(capability)
    if cap is None:
        error = _unknown_capability_error(capability)
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code)
    pinned = set_favorite_capability(cap.id, favorite=True)
    _emit(
        ctx,
        {"ok": True, "capability": cap.id, "favorites": pinned},
        Panel(f"Pinned {cap.id}.", title="Pinned capabilities"),
    )


@favorites_app.command("remove")
def favorites_remove(ctx: typer.Context, capability: str = typer.Argument(...)) -> None:
    """Unpin a capability."""
    from adaf_attack.core.user_config import set_favorite_capability

    pinned = set_favorite_capability(capability, favorite=False)
    _emit(
        ctx,
        {"ok": True, "capability": capability, "favorites": pinned},
        Panel(f"Unpinned {capability}.", title="Pinned capabilities"),
    )


@app.command("targets")
def targets(ctx: typer.Context) -> None:
    """List recently used non-secret target identifiers."""
    from adaf_attack.core.user_config import recent_targets

    entries = recent_targets()
    lines = [f"{item['domain']} @ {item['dc_ip']}  scope={item['scope']}" for item in entries]
    _emit(
        ctx,
        {"ok": True, "targets": entries, "count": len(entries)},
        Panel(
            "\n".join(lines)
            or "No saved targets. Target identifiers are recorded when a TUI or CLI run starts; credentials are never saved here.",
            title="Recent targets",
        ),
    )


@app.command("search")
def search(ctx: typer.Context, query: str = typer.Argument(...)) -> None:
    """Search registered capabilities."""
    from adaf_attack.core.ux import unified_search

    payload = unified_search(query)
    lines = [f"{item['id']}: {item['summary']}" for item in payload["capabilities"]]
    _emit(ctx, {"ok": True, **payload}, Panel("\n".join(lines) or "No matches.", title="Search"))


@app.command("sessions")
def sessions(
    ctx: typer.Context,
    workspace: Path | None = typer.Option(None, "--workspace"),
    session_id: str | None = typer.Option(
        None, "--session", help="Show one session's metadata and event status."
    ),
    limit: int | None = typer.Option(None, "--limit", help="Show only the N most recent sessions."),
    since: str | None = typer.Option(
        None,
        "--since",
        help="Show only sessions created after this cutoff. Accepts 24h, 7d, or an ISO datetime.",
    ),
) -> None:
    """Navigate persisted sessions and report cleanup status (read-only)."""
    root = workspace or default_workspace_dir()
    cutoff = _parse_since(since) if since else None
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
            created_at = meta.get("created_at")
            if cutoff and created_at:
                try:
                    dt = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=UTC)
                    if dt < cutoff:
                        continue
                except ValueError:
                    pass
            entry = {
                "session_id": meta.get("session_id", path.name),
                "created_at": created_at,
                "path": str(path),
                "events_present": events.is_file(),
                "bytes": sum(p.stat().st_size for p in path.rglob("*") if p.is_file()),
            }
            entries.append(entry)
    if session_id:
        entries = [entry for entry in entries if entry["session_id"] == session_id]
    if limit is not None and limit > 0:
        entries = entries[:limit]
    total_bytes = sum(entry["bytes"] for entry in entries)
    payload = {
        "ok": True,
        "workspace": str(root),
        "sessions": entries,
        "cleanup": {
            "action": "read-only status",
            "session_count": len(entries),
            "bytes": total_bytes,
            "bytes_human": _humanize_bytes(total_bytes),
            "next_step": "Review session paths, then remove only explicitly selected sessions outside this command.",
        },
    }
    table = Table(title="Workspace sessions", show_header=True)
    table.add_column("Session")
    table.add_column("Created")
    table.add_column("Age")
    table.add_column("Events")
    table.add_column("Size", justify="right")
    for entry in entries:
        table.add_row(
            entry["session_id"],
            str(entry["created_at"] or "unknown"),
            _humanize_since(entry["created_at"]),
            "yes" if entry["events_present"] else "no",
            _humanize_bytes(entry["bytes"]),
        )
    _emit(ctx, payload, table)


@app.command("cleanup")
def cleanup_cmd(
    ctx: typer.Context,
    session: Path = typer.Option(..., "--session"),
    domain: str = typer.Option(..., "--domain", "-d"),
    dc_ip: str = typer.Option(..., "--dc-ip"),
    username: str | None = typer.Option(None, "--username", "-u"),
    password: str | None = typer.Option(None, "--password", "-p"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    """Execute recorded session rollbacks; requires explicit force."""
    if not force:
        raise typer.BadParameter("cleanup execution requires --force")
    from adaf_attack.core.cleanup import execute_cleanup

    result = execute_cleanup(
        session, Target(domain=domain, dc_ip=dc_ip, username=username, password=password)
    )
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


def _parse_payload(text: str) -> str:
    """Resolve --payload text. '@path' reads a file; anything else is literal.

    A missing @path raises typer.BadParameter with a clear message rather than
    silently degrading to inline text (which used to happen).
    """
    if text.startswith("@"):
        p = Path(text[1:]).expanduser()
        if not p.is_file():
            raise typer.BadParameter(
                f"--payload references a file but path does not exist: {p}. "
                "Drop the '@' prefix to pass literal text."
            )
        return p.read_text(encoding="utf-8")
    return text


def _parse_extra_params(params: list[str] | None) -> dict[str, str]:
    """Parse repeatable --param key=value into a dict."""
    result: dict[str, str] = {}
    if not params:
        return result
    for item in params:
        if "=" not in item:
            raise typer.BadParameter(
                f"--param expects key=value (got {item!r})", param_hint="--param"
            )
        key, _, value = item.partition("=")
        key = key.strip()
        if not key:
            raise typer.BadParameter("--param key cannot be empty", param_hint="--param")
        result[key] = value
    return result


def _interactive_run_prompts(
    ctx: typer.Context,
    capability_id: str,
    *,
    provided: dict[str, Any],
    force_already: bool,
) -> dict[str, Any]:
    """Guided prompt loop for `run --interactive`.

    Resolves the capability, prompts for every required option not already
    supplied on the command line, previews the assembled command with the
    plain-language safety summary, and requires confirmation before returning.
    Raises typer.Exit on user abort.
    """
    import adaf_attack.capabilities  # noqa: F401
    from adaf_attack.core.novice import (
        glossary_definition,
        plain_description,
        required_prompts,
        safety_summary,
    )
    from adaf_attack.core.registry import capability_registry
    from adaf_attack.core.ux import build_ready_command

    cap = capability_registry.get(capability_id)
    if cap is None:
        error = _unknown_capability_error(capability_id)
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code)

    console_obj = _console(ctx)
    safety = safety_summary(cap)
    palette = {"GREEN": "green", "YELLOW": "yellow", "RED": "red"}
    color = palette.get(str(safety["level"]), "white")
    console_obj.print(
        Panel(
            f"[bold]{cap.id}[/bold]  [{color}]{safety['level']}[/{color}]\n"
            f"{plain_description(cap)}\n"
            f"Network contact: {'yes' if safety['network'] else 'no'}",
            title="Interactive run",
        )
    )

    collected: dict[str, Any] = {}
    extra_params: list[str] = []
    for prompt in required_prompts(cap):
        option = prompt["option"]
        # Only ask for --force explicitly for destructive capabilities.
        if option == "--force":
            if force_already:
                continue
            answer = typer.prompt(prompt["label"], default="NO")
            if str(answer).strip().upper() == "YES":
                collected["--force"] = True
            else:
                error = error_for(
                    "USER_ABORTED",
                    message="Destructive-force confirmation declined.",
                )
                _emit_error(ctx, error)
                raise typer.Exit(code=error.exit_code)
            continue

        if prompt["is_param"]:
            key = prompt["param_key"]
            console_obj.print(f"  [dim]{prompt['help']}[/dim]")
            answer = typer.prompt(prompt["label"], default="")
            if answer:
                extra_params.append(f"{key}={answer}")
            continue

        current = provided.get(option)
        if current:
            console_obj.print(f"[dim]{option} already provided: {current}[/dim]")
            continue

        glossary = glossary_definition(option.replace("-", "").lower()) or glossary_definition(
            cap.id
        )
        console_obj.print(f"  [dim]{prompt['help']}[/dim]")
        if glossary:
            console_obj.print(f"  [dim]Glossary: {glossary}[/dim]")
        hidden = option == "--password"
        answer = typer.prompt(prompt["label"], default="", hide_input=hidden, show_default=False)
        if answer:
            collected[option] = answer

    if extra_params:
        collected["__extra_params__"] = extra_params

    # Build the ready command preview using the collected + provided values.
    def _pick(key: str) -> str | None:
        val = collected.get(key)
        if val is None:
            val = provided.get(key)
        if isinstance(val, str) and val:
            return val
        return None

    preview_extra: dict[str, str] = {}
    for entry in extra_params:
        key, _, value = entry.partition("=")
        if key and value:
            preview_extra[key] = value
    ready = build_ready_command(
        cap.id,
        domain=_pick("--domain"),
        dc_ip=_pick("--dc-ip"),
        username=_pick("--username"),
        force=force_already or bool(collected.get("--force")),
        extra=preview_extra or None,
    )
    console_obj.print(
        Panel(
            f"[bold]About to run[/bold]\n{ready}\n\nReview the command above. Nothing has run yet.",
            title="Confirm",
            border_style=color,
        )
    )
    if not typer.confirm("Execute this command now?", default=False):
        error = ActionableError(
            "USER_ABORTED",
            "User declined the interactive run confirmation.",
            "Re-run without --interactive when you have prepared the flags.",
        )
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code)
    return collected


@app.command("run")
def run_capability(
    ctx: typer.Context,
    capability: str = typer.Argument(..., help="Capability ID (see list-capabilities)"),
    domain: str | None = typer.Option(None, "--domain", "-d", help="Target domain"),
    dc_ip: str | None = typer.Option(None, "--dc-ip", help="Domain controller IP or hostname"),
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
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip the interactive destructive-run confirmation."
    ),
    interactive: bool = typer.Option(
        False,
        "--interactive",
        "-i",
        help="Guided run: prompt for required options in plain language and preview the command.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Preview the plan and exit without contacting a target."
    ),
    why: bool = typer.Option(
        False,
        "--why",
        help="Explain purpose, network contact, mutation risk, and evidence before running.",
    ),
    i_understand: bool = typer.Option(
        False, "--i-understand", help="Acknowledge first destructive use in this workspace."
    ),
    include_secrets: bool = typer.Option(
        False, "--include-secrets", help="Do not redact tickets/hashes in output"
    ),
    workspace: Path | None = typer.Option(
        None,
        "--workspace",
        help="Session root directory (default: platform data dir / workspaces)",
    ),
    creds_file: Path | None = typer.Option(
        None,
        "--creds-file",
        help="JSON file with multiple credentials (rotated until LDAP bind succeeds)",
    ),
    param: list[str] | None = typer.Option(
        None,
        "--param",
        "-P",
        help="Extra capability parameter as key=value; repeat as needed (e.g. -P template=User).",
    ),
    graph: Path | None = typer.Option(None, "--graph", hidden=True),
    start: str | None = typer.Option(None, "--start", hidden=True),
    max_depth: int = typer.Option(6, "--max-depth", hidden=True),
    limit: int = typer.Option(25, "--limit", hidden=True),
    scope: str = typer.Option("high-value", "--scope", hidden=True),
    max_objects: int = typer.Option(500, "--max-objects", hidden=True),
    template: str | None = typer.Option(None, "--template", hidden=True),
    ca: str | None = typer.Option(None, "--ca", hidden=True),
    alt_name: str | None = typer.Option(None, "--alt-name", hidden=True),
    write_target: str | None = typer.Option(None, "--write-target", hidden=True),
    attribute: str | None = typer.Option(None, "--attribute", hidden=True),
    value: str | None = typer.Option(None, "--value", hidden=True),
    descriptor_hex: str | None = typer.Option(None, "--descriptor-hex", hidden=True),
    set_on: str | None = typer.Option(None, "--set-on", hidden=True),
    set_from: str | None = typer.Option(None, "--set-from", hidden=True),
    sam: str | None = typer.Option(None, "--sam", hidden=True),
    key: str | None = typer.Option(None, "--key", hidden=True),
    cert: str | None = typer.Option(None, "--cert", hidden=True),
    pfx: str | None = typer.Option(None, "--pfx", hidden=True),
    gpo: str | None = typer.Option(None, "--gpo", hidden=True),
    payload: str | None = typer.Option(None, "--payload", hidden=True),
    operation: str | None = typer.Option(None, "--operation", hidden=True),
    artifact: str | None = typer.Option(None, "--artifact", hidden=True),
    impersonate: str | None = typer.Option(None, "--impersonate", hidden=True),
    spn: str | None = typer.Option(None, "--spn", hidden=True),
) -> None:
    """Run a capability against a target.

    Use `-P key=value` (repeatable) for capability-specific parameters instead
    of a long list of flags. See `capability-help <id>` for what each capability
    accepts.
    """
    defaults = load_user_config()
    if domain is None:
        domain = defaults.get("target.domain")
    if dc_ip is None:
        dc_ip = defaults.get("target.dc_ip")
    if username is None:
        username = defaults.get("target.username")
    if not use_kerberos and defaults.get("target.kerberos"):
        use_kerberos = bool(defaults.get("target.kerberos"))
    if not ldaps and defaults.get("target.ldaps"):
        ldaps = bool(defaults.get("target.ldaps"))

    if interactive:
        non_interactive_ctx = ctx.ensure_object(dict).get("non_interactive")
        if non_interactive_ctx or _json_mode(ctx):
            error = ActionableError(
                "INTERACTIVE_MODE_DISABLED",
                "--interactive cannot combine with --format json or --non-interactive.",
                "Remove --interactive, or drop --non-interactive / --format json.",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        collected = _interactive_run_prompts(
            ctx,
            capability,
            provided={
                "--domain": domain,
                "--dc-ip": dc_ip,
                "--username": username,
                "--password": password,
                "--hashes": hashes,
                "--ccache": ccache,
                "--sam": sam,
                "--template": template,
                "--ca": ca,
                "--alt-name": alt_name,
                "--write-target": write_target,
                "--descriptor-hex": descriptor_hex,
                "--set-on": set_on,
                "--set-from": set_from,
                "--gpo": gpo,
                "--payload": payload,
                "--operation": operation,
            },
            force_already=force,
        )
        # Overwrite fields the user supplied at the prompt.
        domain = collected.get("--domain", domain)
        dc_ip = collected.get("--dc-ip", dc_ip)
        username = collected.get("--username", username)
        password = collected.get("--password", password)
        hashes = collected.get("--hashes", hashes)
        ccache = collected.get("--ccache", ccache)
        sam = collected.get("--sam", sam)
        template = collected.get("--template", template)
        ca = collected.get("--ca", ca)
        alt_name = collected.get("--alt-name", alt_name)
        write_target = collected.get("--write-target", write_target)
        descriptor_hex = collected.get("--descriptor-hex", descriptor_hex)
        set_on = collected.get("--set-on", set_on)
        set_from = collected.get("--set-from", set_from)
        gpo = collected.get("--gpo", gpo)
        payload = collected.get("--payload", payload)
        operation = collected.get("--operation", operation)
        if collected.get("--force"):
            force = True
        # -P style params captured during the prompt are appended.
        extra_params = collected.get("__extra_params__") or []
        if extra_params:
            merged = list(param or [])
            merged.extend(extra_params)
            param = merged

    if not domain or not dc_ip:
        raise typer.BadParameter(
            "--domain and --dc-ip are required (or set via `adaf-attack config set`)"
        )

    from adaf_attack.core.user_config import record_recent_target

    record_recent_target(domain, dc_ip, scope)

    if dry_run:
        return plan(
            ctx, capability=capability, domain=domain, dc_ip=dc_ip, force=force, export=None
        )

    target = _build_target(
        domain, dc_ip, username, password, hashes, aes_key, ccache, use_kerberos, ldaps
    )

    # Resolve capability early so we can gate confirmation
    import adaf_attack.capabilities  # noqa: F401
    from adaf_attack.core.registry import capability_registry

    cap = capability_registry.get(capability)

    guided_mode = bool(interactive)
    non_interactive = ctx.ensure_object(dict).get("non_interactive")
    interactive = (not non_interactive) and sys.stdout.isatty() and not _json_mode(ctx)

    if cap is not None and why and not _json_mode(ctx):
        _console(ctx).print(Panel(_why_text(cap), title=f"Why: {capability}"))
    if cap is not None and cap.destructive and force and interactive and not yes:
        _console(ctx).print(
            Panel(
                f"[bold red]DESTRUCTIVE[/bold red] {capability} against {domain} @ {dc_ip}\n"
                "This may modify the target. Re-run with --yes to skip this prompt.",
                title="Confirm",
            )
        )
        if not typer.confirm("Continue?", default=False):
            error = ActionableError(
                "USER_ABORTED",
                "User declined the destructive-run confirmation prompt.",
                "Re-run with --yes to skip this prompt when execution is authorized.",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)

    if cap is not None and cap.destructive and force:
        # The existing interactive "Continue?" confirmation is itself an
        # explicit acknowledgement; --yes bypasses it and therefore requires
        # the stronger capability-name acknowledgement.
        _require_destructive_ack(
            ctx,
            capability,
            workspace or default_workspace_dir(),
            explicit=i_understand or (guided_mode and not yes),
            interactive=interactive or guided_mode,
        )

    if not _json_mode(ctx):
        if cap is not None:
            from adaf_attack.core.novice import capability_difficulty
            from adaf_attack.core.ux import format_stages_progress, risk_checklist

            checklist = risk_checklist(cap)
            stages = format_stages_progress(cap)
            required_items = [item["label"] for item in checklist["items"] if item["required"]]
            _console(ctx).print(
                Panel(
                    "\n".join(
                        [
                            f"Difficulty: {capability_difficulty(cap)['level']}",
                            "Preflight: " + ", ".join(required_items),
                            "Stages: " + " -> ".join(item["id"] for item in stages["stages"]),
                        ]
                    ),
                    title="Preflight checklist",
                )
            )
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
    for name, val in (
        ("template", template),
        ("ca", ca),
        ("alt_name", alt_name),
        ("write_target", write_target),
        ("attribute", attribute),
        ("value", value),
        ("descriptor_hex", descriptor_hex),
        ("set_on", set_on),
        ("set_from", set_from),
        ("sam", sam),
        ("key", key),
        ("cert", cert),
        ("pfx", pfx),
        ("gpo", gpo),
        ("operation", operation),
        ("artifact", artifact),
        ("impersonate", impersonate),
        ("spn", spn),
    ):
        if val:
            extra[name] = val
    if payload is not None:
        extra["payload"] = _parse_payload(payload)

    # -P/--param overrides take precedence over legacy flags.
    extra.update(_parse_extra_params(param))

    try:
        if _json_mode(ctx) or not interactive:
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
        else:
            out = _execute_with_spinner(
                ctx, capability, target, force, include_secrets, workspace, creds_file, extra
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
        session_id = out.get("session_id")
        if session_id:
            _console(ctx).print(f"Inspect: adaf-attack sessions --session {session_id}")
    except RunError as exc:
        text = str(exc)
        code = classify_run_error(text)
        if text.startswith("Unknown capability:"):
            error = _unknown_capability_error(capability)
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        elif "DESTRUCTIVE" in text and "--force" in text:
            code = "DESTRUCTIVE_CONFIRMATION_REQUIRED"
        elif "no runner implemented" in text:
            code = "CAPABILITY_UNAVAILABLE"
        error = error_for(code, message=text, details={"capability": capability})
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from exc


def _execute_with_spinner(
    ctx: typer.Context,
    capability: str,
    target: Target,
    force: bool,
    include_secrets: bool,
    workspace: Path | None,
    creds_file: Path | None,
    extra: dict[str, Any],
) -> dict[str, Any]:
    """Run a capability inside a Rich spinner, threading log messages into the status."""
    console_obj = _console(ctx)
    stage_hint = capability
    try:
        from adaf_attack.core.registry import capability_registry
        from adaf_attack.core.ux import format_stages_progress

        cap = capability_registry.get(capability)
        if cap is not None:
            stage_hint = " -> ".join(item["id"] for item in format_stages_progress(cap)["stages"])
    except Exception:  # noqa: BLE001
        stage_hint = capability
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console_obj,
        transient=True,
    ) as progress:
        task_id = progress.add_task(f"Running {capability}: {stage_hint}", total=None)

        def _log(message: str) -> None:
            progress.update(task_id, description=f"{capability}: {message[:80]}")

        return execute_capability(
            capability,
            target,
            force=force,
            include_secrets=include_secrets,
            workspace=workspace,
            creds_file=creds_file,
            log=_log,
            **extra,
        )


@engagement_app.command("init")
def engagement_init(
    output: Path = typer.Option(Path("engagement.yaml"), "--output", "-o"),
    template: str = typer.Option("standard", "--template", help="standard or ad-recon"),
) -> None:
    """Write a conservative engagement-plan template."""
    if output.exists():
        raise typer.BadParameter(f"Refusing to overwrite existing file: {output}")
    if template not in {"standard", "ad-recon"}:
        raise typer.BadParameter("--template must be 'standard' or 'ad-recon'")
    if template == "ad-recon":
        from adaf_attack.core.workflows import ad_recon_plan_data

        plan = ad_recon_plan_data()
        output.write_text(
            "# Read-only AD reconnaissance. Complete and review this scope before running.\n"
            + __import__("yaml").safe_dump(plan, sort_keys=False),
            encoding="utf-8",
        )
    else:
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


@ad_recon_app.command("init")
def ad_recon_init(
    output: Path = typer.Option(Path("ad-recon.yaml"), "--output", "-o"),
) -> None:
    """Write the reviewed, read-only AD reconnaissance engagement template."""
    engagement_init(output=output, template="ad-recon")


@ad_recon_app.command("profile")
def ad_recon_profile(ctx: typer.Context) -> None:
    """Show the ordered AD reconnaissance collection baseline (no network)."""
    from adaf_attack.core.workflows import AD_RECON_PHASES, ad_recon_plan_data

    plan = ad_recon_plan_data()
    _emit(
        ctx,
        {"ok": True, "read_only": True, "plan": plan},
        Panel(
            "\n".join(
                f"{phase['name']}: {', '.join(phase['capabilities'])}" for phase in AD_RECON_PHASES
            )
            + "\n\nCreates one shared session graph; no secrets are requested.",
            title="AD reconnaissance baseline (read-only)",
        ),
    )


@engagement_app.command("validate")
def engagement_validate(ctx: typer.Context, plan: Path = typer.Argument(...)) -> None:
    """Validate a plan without contacting a target."""
    from adaf_attack.core.engagement import EngagementError, load_plan

    try:
        value = load_plan(plan)
    except EngagementError as exc:
        error = ActionableError(
            "ENGAGEMENT_PLAN_INVALID", str(exc), "Correct the YAML scope and validate again."
        )
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from exc
    _emit(
        ctx,
        {
            "ok": True,
            "engagement_id": value.engagement_id,
            "target": value.dc_ip,
            "allowed_capabilities": list(value.allowed_capabilities),
            "phase_count": len(value.phases),
        },
        Panel(
            f"{value.engagement_id}\nTarget: {value.domain} @ {value.dc_ip}\nPhases: {len(value.phases)}",
            title="Engagement plan valid",
        ),
    )


@engagement_app.command("run")
def engagement_run(
    ctx: typer.Context,
    plan: Path = typer.Argument(...),
    workspace: Path = typer.Option(Path("workspaces"), "--workspace"),
    username: str | None = typer.Option(None, "--username", "-u"),
    password: str | None = typer.Option(None, "--password", "-p"),
    approval_token: str | None = typer.Option(
        None, "--approval-token", envvar="ADAF_APPROVAL_TOKEN"
    ),
) -> None:
    """Execute only the capabilities authorized by a validated engagement plan."""
    from adaf_attack.core.engagement import EngagementError, load_plan, run_engagement

    try:
        result = run_engagement(
            load_plan(plan),
            workspace=workspace,
            username=username,
            password=password,
            approval_token=approval_token,
        )
    except EngagementError as exc:
        error = ActionableError(
            "ENGAGEMENT_RUN_BLOCKED",
            str(exc),
            "Review target scope, authorization, and phase configuration.",
        )
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from exc
    _emit(
        ctx,
        {"ok": True, **result},
        Panel(
            f"Engagement: {result['engagement_id']}\nCapabilities: {len(result['capabilities'])}\nFindings: {result['finding_count']}\nSession: {result['session_path']}",
            title="Engagement complete",
        ),
    )


@engagement_app.command("report")
def engagement_report(
    ctx: typer.Context,
    session: Path = typer.Option(..., "--session"),
    engagement_id: str = typer.Option("unassigned", "--engagement-id"),
) -> None:
    """Generate executive, technical, and remediation HTML/PDF reports from evidence."""
    from adaf_attack.core.reporting import generate_report_bundle

    if not session.is_dir():
        error = ActionableError(
            "SESSION_NOT_FOUND",
            "The session directory does not exist.",
            "Pass a completed engagement session with --session.",
        )
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code)
    result = generate_report_bundle(session, engagement_id=engagement_id)
    _emit(
        ctx,
        {"ok": True, **result},
        Panel(
            f"Findings: {result['finding_count']}\nReport directory: {session / 'reports'}",
            title="Client report bundle",
        ),
    )


@engagement_app.command("package")
def engagement_package(
    ctx: typer.Context,
    session: Path = typer.Option(..., "--session"),
    output: Path = typer.Option(Path("engagement-package.zip"), "--output", "-o"),
    profile: str = typer.Option("client", "--profile", help="operator, purple, or client"),
    preview: bool = typer.Option(
        False, "--preview", help="Preview excluded/redacted files without creating an archive."
    ),
) -> None:
    """Create a redacted evidence archive without including the session vault."""
    from adaf_attack.core.control_plane import package_evidence

    if preview:
        from adaf_attack.core.redaction import redact

        if not session.is_dir():
            raise typer.BadParameter("Session directory does not exist", param_hint="--session")
        excluded: list[str] = []
        redactions: list[str] = []
        for path in sorted(session.rglob("*")):
            if not path.is_file() or "vault" in path.parts:
                continue
            if path.suffix.lower() in {
                ".ccache",
                ".kirbi",
                ".key",
                ".pfx",
                ".pem",
                ".pvk",
                ".secrets",
            } or path.name.lower() in {
                "asrep-roast.hashes.txt",
                "kerberoast.hashes.txt",
                "ntlm.hashes.txt",
            }:
                excluded.append(str(path.relative_to(session)))
            elif path.suffix.lower() == ".json":
                try:
                    raw = json.loads(path.read_text(encoding="utf-8"))
                    safe = redact(raw, profile=profile)
                    redactions.extend(
                        item["path"]
                        for item in _redaction_changes(raw, safe, str(path.relative_to(session)))
                    )
                except (OSError, json.JSONDecodeError, ValueError):
                    excluded.append(str(path.relative_to(session)))
        preview_payload = {
            "ok": True,
            "preview": True,
            "output": str(output.resolve()),
            "excluded_files": excluded,
            "redacted_fields": redactions,
        }
        _emit(
            ctx,
            preview_payload,
            Panel(
                f"No archive written. Excluded files: {len(excluded)}\nRedacted fields: {len(redactions)}",
                title="Evidence sharing preview",
            ),
        )
        return

    try:
        result = package_evidence(session, output, profile=profile)
    except ValueError as exc:
        error = ActionableError(
            "ENGAGEMENT_PACKAGE_FAILED", str(exc), "Use an existing session and redaction profile."
        )
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from exc
    _emit(
        ctx,
        {"ok": True, **result},
        Panel(
            f"Archive: {result['archive']}\nFiles: {result['file_count']}\nProfile: {result['profile']}",
            title="Engagement evidence package",
        ),
    )


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
    except ActionableError as caught:
        _emit_error(ctx, caught)
        raise typer.Exit(code=caught.exit_code) from caught
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
def forest_campaign_cmd(
    ctx: typer.Context, session: list[Path] = typer.Option(..., "--session")
) -> None:
    """Compose a forest-aware, read-only campaign from completed sessions."""
    from adaf_attack.core.forest_campaign import compose_forest_campaign

    try:
        payload = compose_forest_campaign(_offline_sessions(session))
    except (ActionableError, ValueError) as exc:
        error = ActionableError(
            "FOREST_CAMPAIGN_FAILED", str(exc), "Pass completed, authorized session directories."
        )
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from exc
    _emit(
        ctx,
        {"ok": True, **payload},
        Panel(
            f"Domains: {len(payload['domains'])}\nTrust transitions: {len(payload['trust_transitions'])}",
            title="Forest-aware campaign",
        ),
    )


@app.command("campaign-run")
def campaign_run_cmd(
    ctx: typer.Context,
    campaign: Path = typer.Option(
        ..., "--campaign", help="Campaign YAML with ordered engagement plans"
    ),
    workspace: Path = typer.Option(Path("workspaces"), "--workspace"),
    username: str | None = typer.Option(None, "--username", "-u"),
    password: str | None = typer.Option(None, "--password", "-p"),
    approval_tokens: Path | None = typer.Option(
        None,
        "--approval-tokens",
        help="JSON mapping of engagement ID to approval token",
    ),
) -> None:
    """Run ordered, independently scoped engagement plans from a campaign YAML."""
    from adaf_attack.core.forest_campaign import CampaignError, run_campaign

    try:
        token_map = (
            json.loads(approval_tokens.read_text(encoding="utf-8"))
            if approval_tokens is not None
            else {}
        )
        if not isinstance(token_map, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in token_map.items()
        ):
            raise CampaignError(
                "--approval-tokens must be a JSON object of engagement IDs to tokens"
            )
        payload = run_campaign(
            campaign,
            workspace=workspace,
            username=username,
            password=password,
            approval_tokens=token_map,
        )
    except (CampaignError, OSError, json.JSONDecodeError) as exc:
        error = ActionableError(
            "CAMPAIGN_RUN_FAILED",
            str(exc),
            "Validate the campaign plans, scopes, and approval-token mapping.",
        )
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from exc
    _emit(
        ctx,
        {"ok": not payload["stopped"], **payload},
        Panel(
            f"Campaign: {payload['campaign_id']}\nCompleted: {len(payload['completed'])}\n"
            f"Stopped: {'yes' if payload['stopped'] else 'no'}",
            title="Campaign runner",
        ),
    )


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


@app.command("errors")
def show_errors(
    ctx: typer.Context,
    code: str | None = typer.Argument(None, help="Optional error code to show in detail."),
) -> None:
    """List error codes and their remediation."""
    if code and code not in ERROR_CATALOG:
        error = ActionableError(
            "UNKNOWN_ERROR_CODE",
            f"Unknown error code: {code}",
            "Run `adaf-attack errors` to list valid codes.",
        )
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code)
    catalog = {code: ERROR_CATALOG[code]} if code else dict(sorted(ERROR_CATALOG.items()))
    payload = {
        "ok": True,
        "count": len(catalog),
        "errors": [
            {
                "code": key,
                "message": entry[0],
                "remediation": entry[1],
                "suggested_command": entry[2] if len(entry) > 2 else None,
            }
            for key, entry in catalog.items()
        ],
    }
    table = Table(title="ADAF-ATTACK error codes", show_header=True)
    table.add_column("Code", style="cyan")
    table.add_column("Message")
    table.add_column("Remediation")
    for key, entry in catalog.items():
        table.add_row(key, entry[0], entry[1])
    _emit(ctx, payload, table)


@app.command("glossary")
def glossary_cmd(
    ctx: typer.Context,
    term: str | None = typer.Argument(None, help="Term to explain; omit to list all terms."),
) -> None:
    """Explain Active Directory and operator terms in plain language."""
    from adaf_attack.core.novice import glossary_definition, glossary_items

    items = glossary_items()
    if term:
        definition = glossary_definition(term)
        if definition is None:
            error = ActionableError(
                "UNKNOWN_GLOSSARY_TERM",
                f"Unknown glossary term: {term}",
                "Run `adaf-attack glossary` to list available terms.",
                suggested_command="adaf-attack glossary",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        payload = {"ok": True, "term": term.lower(), "definition": definition}
        _emit(ctx, payload, Panel(f"{term.upper()}: {definition}", title="Glossary"))
        return
    payload = {"ok": True, "count": len(items), "terms": items}
    table = Table(title="ADAF-ATTACK glossary", show_header=True)
    table.add_column("Term", style="cyan")
    table.add_column("Plain meaning")
    for key, definition in items.items():
        table.add_row(key.upper(), definition)
    _emit(ctx, payload, table)


@app.command("home")
def home_cmd(ctx: typer.Context) -> None:
    """Show plain-language goals for users who do not know the command names."""
    from adaf_attack.core.novice import home_actions

    doctor_payload = _doctor_payload("offline")
    actions = home_actions(first_run=bool(doctor_payload["first_run"]))
    payload = {
        "ok": True,
        "first_run": doctor_payload["first_run"],
        "actions": actions,
        "next_step": actions[0]["command"],
    }
    table = Table(title="What should I do?", show_header=True)
    table.add_column("Goal", style="cyan")
    table.add_column("Command")
    table.add_column("Why")
    for action in actions:
        table.add_row(action["goal"], action["command"], action["why"])
    _emit(ctx, payload, table)


@app.command("command")
def command_builder_cmd(
    ctx: typer.Context,
    capability: str = typer.Argument(..., help="Capability ID to build a command for."),
    domain: str | None = typer.Option(None, "--domain", "-d"),
    dc_ip: str | None = typer.Option(None, "--dc-ip"),
    username: str | None = typer.Option(None, "--username", "-u"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    """Generate a copy-ready command and explain each option in plain language."""
    import adaf_attack.capabilities  # noqa: F401
    from adaf_attack.core.novice import command_option_explanations
    from adaf_attack.core.registry import capability_registry
    from adaf_attack.core.ux import build_ready_command

    cap = capability_registry.get(capability)
    if cap is None:
        error = _unknown_capability_error(capability)
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code)
    ready = build_ready_command(
        cap.id,
        domain=domain or "<domain>",
        dc_ip=dc_ip or "<dc-ip>",
        username=username,
        force=force or cap.destructive,
    )
    explanations = command_option_explanations(cap)
    payload = {
        "ok": True,
        "capability": cap.id,
        "command": ready,
        "option_explanations": explanations,
        "next_step": "Review scope, then run the command only against an authorized target.",
    }
    lines = [ready, "", "Options:"]
    for item in explanations:
        required = "required" if item["required"] == "true" else "optional"
        lines.append(f"{item['option']}: {item['label']} ({required})")
    _emit(ctx, payload, Panel("\n".join(lines), title=f"Command builder: {cap.id}"))


finding_app = typer.Typer(help="Explain findings and build remediation checklists.")
app.add_typer(finding_app, name="finding")


def _load_session_finding(session: Path, finding_id: str) -> dict[str, Any]:
    try:
        payload = json.loads((session / "findings.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ActionableError(
            "SESSION_NOT_FOUND",
            "Could not read findings.json from the session.",
            "Pass a completed session directory with --session.",
            details={"session": str(session), "error": str(exc)},
        ) from exc
    findings = payload.get("findings") if isinstance(payload, dict) else payload
    if not isinstance(findings, list):
        findings = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        aliases = {
            str(finding.get("id") or ""),
            str(finding.get("finding_id") or ""),
            str(finding.get("title") or ""),
        }
        if finding_id in aliases:
            return finding
    raise ActionableError(
        "UNKNOWN_FINDING",
        f"Finding not found: {finding_id}",
        "Run `adaf-attack session show --session <dir>` to list finding IDs.",
        details={"session": str(session), "finding": finding_id},
    )


@finding_app.command("explain")
def finding_explain_cmd(
    ctx: typer.Context,
    session: Path = typer.Option(..., "--session"),
    finding_id: str = typer.Option(..., "--id", help="Finding ID or exact title."),
) -> None:
    """Explain a saved finding in plain English."""
    from adaf_attack.core.novice import explain_finding_payload

    try:
        explanation = explain_finding_payload(_load_session_finding(session, finding_id))
    except ActionableError as error:
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from error
    payload = {"ok": True, "finding": explanation}
    lines = [
        f"{explanation['id']}: {explanation['title']}",
        f"Severity: {explanation['severity']}",
        f"Meaning: {explanation['meaning']}",
        f"Why it matters: {explanation['why_it_matters']}",
        f"Next: {explanation['recommended_next_step']}",
    ]
    _emit(ctx, payload, Panel("\n".join(lines), title="Finding explainer"))


@finding_app.command("remediate")
def finding_remediate_cmd(
    ctx: typer.Context,
    session: Path = typer.Option(..., "--session"),
    finding_id: str = typer.Option(..., "--id", help="Finding ID or exact title."),
) -> None:
    """Turn a saved finding into a remediation checklist."""
    from adaf_attack.core.novice import remediation_checklist

    try:
        checklist = remediation_checklist(_load_session_finding(session, finding_id))
    except ActionableError as error:
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from error
    payload = {"ok": True, **checklist}
    lines = [f"{step['id']}: {step['label']}" for step in checklist["steps"]]
    _emit(ctx, payload, Panel("\n".join(lines), title="Remediation checklist"))


@finding_app.command("triage")
def finding_triage_cmd(
    ctx: typer.Context,
    session: Path = typer.Option(..., "--session"),
    finding_id: str = typer.Option(..., "--id", help="Finding ID or exact title."),
    status: str | None = typer.Option(
        None, "--status", help="open | acknowledged | remediated | accepted-risk"
    ),
    tag: str | None = typer.Option(None, "--tag", help="Add an operator tag."),
    note: str | None = typer.Option(None, "--note", help="Replace the operator triage note."),
    owner: str | None = typer.Option(
        None, "--owner", help="Assign an owner for collaborative triage."
    ),
    comment: str | None = typer.Option(None, "--comment", help="Add a collaboration comment."),
) -> None:
    """View or update the durable triage state for one finding."""
    allowed = {"open", "acknowledged", "remediated", "accepted-risk"}
    try:
        finding = _load_session_finding(session, finding_id)
    except ActionableError as error:
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from error
    changed = False
    if status is not None:
        if status not in allowed:
            status_error = ActionableError(
                "INVALID_FINDING_STATUS",
                f"Invalid finding status: {status}",
                f"Choose one of: {', '.join(sorted(allowed))}.",
                suggested_command=f"adaf-attack finding triage --session {session} --id {finding_id} --status acknowledged",
            )
            _emit_error(ctx, status_error)
            raise typer.Exit(code=status_error.exit_code)
        finding["status"] = status
        changed = True
    if tag is not None:
        raw_tags = finding.get("tags")
        tags: list[Any] = list(raw_tags) if isinstance(raw_tags, list) else []
        if tag not in tags:
            tags.append(tag)
        finding["tags"] = tags
        changed = True
    if note is not None:
        finding["triage_note"] = note
        changed = True
    if owner is not None:
        finding["owner"] = owner
        changed = True
    if comment is not None:
        finding["comment"] = comment
        changed = True
    if changed:
        try:
            path = session / "findings.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            values = document.get("findings") if isinstance(document, dict) else None
            if not isinstance(values, list):
                raise ValueError("findings.json does not contain a findings list")
            target_key = str(
                finding.get("id") or finding.get("finding_id") or finding.get("title") or ""
            )
            for index, value in enumerate(values):
                value_key = (
                    str(value.get("id") or value.get("finding_id") or value.get("title") or "")
                    if isinstance(value, dict)
                    else ""
                )
                if value_key == target_key:
                    values[index] = finding
                    break
            else:
                raise ValueError("finding disappeared while updating findings.json")
            path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            triage_error = ActionableError(
                "FINDING_TRIAGE_WRITE_FAILED",
                f"Could not update finding triage state: {exc}",
                "Check that the session is writable and rerun the command.",
                suggested_command=f"adaf-attack finding explain --session {session} --id {finding_id}",
            )
            _emit_error(ctx, triage_error)
            raise typer.Exit(code=triage_error.exit_code) from exc
    payload = {
        "ok": True,
        "updated": changed,
        "session": str(session),
        "finding": finding,
        "allowed_statuses": sorted(allowed),
    }
    _emit(
        ctx,
        payload,
        Panel(
            f"{finding.get('id') or finding.get('title')}\nStatus: {finding.get('status', 'open')}\n"
            f"Tags: {', '.join(finding.get('tags') or []) or '-'}\n"
            f"Owner: {finding.get('owner') or '-'}\n"
            f"Note: {finding.get('triage_note') or '-'}\n"
            f"Comment: {finding.get('comment') or '-'}",
            title="Finding triage",
        ),
    )


config_app = typer.Typer(help="Persistent per-user defaults for CLI and TUI.")
app.add_typer(config_app, name="config")


@config_app.command("show")
def config_show(ctx: typer.Context) -> None:
    """Print the persisted configuration."""
    from adaf_attack.core.user_config import config_path

    data = load_user_config()
    payload = {"ok": True, "path": str(config_path()), "config": data}
    if not data:
        human: ConsoleRenderable = Panel(
            f"No configuration set.\nPath: {config_path()}\n"
            "Use `adaf-attack config set <key> <value>` to persist defaults.",
            title="Config (empty)",
        )
    else:
        table = Table(title="Persisted config", show_header=True)
        table.add_column("Key", style="cyan")
        table.add_column("Value")
        for key in sorted(data):
            table.add_row(key, str(data[key]))
        human = table
    _emit(ctx, payload, human)


@config_app.command("set")
def config_set(
    ctx: typer.Context,
    key: str = typer.Argument(..., help="Config key (see `adaf-attack config keys`)."),
    value: str = typer.Argument(..., help="Value to persist."),
) -> None:
    """Persist a per-user default."""
    from adaf_attack.core.user_config import set_key

    try:
        path, data = set_key(key, value)
    except ValueError as exc:
        error = error_for("CONFIG_KEY_INVALID", message=str(exc))
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from exc
    except OSError as exc:
        error = error_for(
            "CONFIG_WRITE_FAILED",
            message=f"Could not write the configuration file: {exc}",
        )
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from exc
    _emit(
        ctx,
        {"ok": True, "path": str(path), "config": data},
        Panel(f"Set {key} = {data[key]}\nPath: {path}", title="Config updated"),
    )


@config_app.command("unset")
def config_unset(ctx: typer.Context, key: str = typer.Argument(...)) -> None:
    """Remove a persisted default."""
    from adaf_attack.core.user_config import unset_key

    try:
        path, data = unset_key(key)
    except OSError as exc:
        error = error_for(
            "CONFIG_WRITE_FAILED",
            message=f"Could not write the configuration file: {exc}",
        )
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code) from exc
    _emit(
        ctx,
        {"ok": True, "path": str(path), "config": data},
        Panel(f"Removed {key}\nPath: {path}", title="Config updated"),
    )


@config_app.command("keys")
def config_keys(ctx: typer.Context) -> None:
    """List allowed configuration keys."""
    from adaf_attack.core.user_config import allowed_keys

    keys = allowed_keys()
    _emit(
        ctx,
        {"ok": True, "keys": keys},
        Panel("\n".join(keys), title="Allowed config keys"),
    )


# --- noun-verb subgroups (aliases for existing commands) ---------------------
capability_app = typer.Typer(help="Capability listing, help, planning, and running.")
session_app = typer.Typer(help="Workspace session inspection.")
path_app = typer.Typer(help="Attack-path ranking.")
app.add_typer(capability_app, name="capability")
app.add_typer(session_app, name="session")
app.add_typer(path_app, name="path")

# Register the optional operator-experience command group after the shared
# output helpers and noun-verb subgroups are available.
register_ux_commands(
    app,
    session_app,
    emit=_emit,
    emit_error=_emit_error,
    json_mode=_json_mode,
    console=_console,
    doctor_payload=lambda *args, **kwargs: _doctor_payload(*args, **kwargs),
)

register_tool_commands(app, emit=_emit, emit_error=_emit_error)
register_product_commands(app, emit=_emit, emit_error=_emit_error)

# Finding-driven guided workflow surface: the CLI/agent client of the same
# durable engine the TUI drives (src/adaf_attack/core/workflow_engine.py).
register_workflow_commands(app, emit=_emit, emit_error=_emit_error)


@capability_app.command("list")
def capability_list_alias(ctx: typer.Context) -> None:
    """Alias for `adaf-attack list-capabilities`."""
    list_capabilities(ctx)


@capability_app.command("show")
def capability_show_alias(
    ctx: typer.Context,
    capability: str | None = typer.Argument(None),
) -> None:
    """Alias for `adaf-attack capability-help`."""
    capability_help(ctx, capability=capability)


@session_app.command("list")
def session_list_alias(
    ctx: typer.Context,
    workspace: Path | None = typer.Option(None, "--workspace"),
    session_id: str | None = typer.Option(None, "--session"),
    limit: int | None = typer.Option(None, "--limit"),
    since: str | None = typer.Option(None, "--since"),
) -> None:
    """Alias for `adaf-attack sessions`."""
    sessions(
        ctx,
        workspace=workspace,
        session_id=session_id,
        limit=limit,
        since=since,
    )


@session_app.command("diff")
def session_diff(
    ctx: typer.Context,
    first: Path = typer.Argument(..., help="First session directory."),
    second: Path = typer.Argument(..., help="Second session directory."),
) -> None:
    """Compare findings and graph sizes between two sessions."""
    from adaf_attack.core.ux import diff_sessions

    payload = diff_sessions(first, second)
    human = Panel(
        "\n".join(
            [
                f"Findings delta: {payload['finding_delta']}",
                f"Nodes delta: {payload['node_delta']}",
                f"Edges delta: {payload['edge_delta']}",
                f"Added findings: {', '.join(payload['findings_added']) or '-'}",
                f"Removed findings: {', '.join(payload['findings_removed']) or '-'}",
            ]
        ),
        title="Session diff",
    )
    _emit(ctx, {"ok": True, **payload}, human)


@session_app.command("resume")
def session_resume(
    ctx: typer.Context,
    session: Path = typer.Option(..., "--session", help="Session directory to resume or inspect."),
) -> None:
    """Show a safe resume package for a prior session without executing anything."""
    from adaf_attack.core.ux import session_findings_dashboard

    if not session.is_dir() or not (session / "session.json").is_file():
        error = error_for("SESSION_NOT_FOUND", details={"session": str(session)})
        _emit_error(ctx, error)
        raise typer.Exit(code=error.exit_code)
    dashboard = session_findings_dashboard(session)
    capabilities: list[str] = []
    events = session / "events.jsonl"
    if events.is_file():
        for line in events.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict) and item.get("capability"):
                value = str(item["capability"])
                if value not in capabilities:
                    capabilities.append(value)
    payload = {
        "ok": True,
        "session": str(session),
        "dashboard": dashboard,
        "capabilities_seen": capabilities,
        "commands": {
            "inspect": f"adaf-attack session show --session {session}",
            "triage": f"adaf-attack finding triage --session {session} --id <finding-id>",
            "report": f"adaf-attack engagement report --session {session}",
        },
        "execution": "not-started",
    }
    _emit(
        ctx,
        payload,
        Panel(
            f"Session: {dashboard.get('session_id') or session.name}\nFindings: {dashboard.get('finding_count', 0)}\n"
            f"Inspect: adaf-attack session show --session {session}\n"
            "No capability was executed; review the plan before continuing.",
            title="Session resume",
        ),
    )


@path_app.command("rank")
def path_rank_alias(
    ctx: typer.Context,
    graph: Path = typer.Option(..., "--graph", "-g"),
    start: str | None = typer.Option(None, "--start", "-s"),
    max_depth: int = typer.Option(6, "--max-depth"),
    limit: int = typer.Option(25, "--limit"),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Alias for `adaf-attack rank-paths`."""
    rank_paths_cmd(
        ctx,
        graph=graph,
        start=start,
        max_depth=max_depth,
        limit=limit,
        output=output,
    )


@app.command("init")
def init_cmd(
    ctx: typer.Context,
    workspace: Path | None = typer.Option(
        None,
        "--workspace",
        help="Preferred workspace directory to save as the default (skipped when not provided).",
    ),
    domain: str | None = typer.Option(
        None, "--domain", help="Default authorized domain to save (skipped when not provided)."
    ),
    dc_ip: str | None = typer.Option(
        None, "--dc-ip", help="Default DC IP or hostname to save (skipped when not provided)."
    ),
    username: str | None = typer.Option(
        None, "--username", help="Default username to save (skipped when not provided)."
    ),
    skip_quickstart: bool = typer.Option(
        False, "--skip-quickstart", help="Do not print the quickstart follow-up command."
    ),
) -> None:
    """First-run onboarding: check the environment, save defaults, point at quickstart.

    Interactive when run on a TTY without --format json; otherwise the flags
    above act as the sole input (safe for scripts and CI). Nothing is written
    unless a value is supplied or accepted at the prompt.
    """
    from adaf_attack.core.user_config import allowed_keys, load_user_config, set_key  # noqa: F401

    non_interactive = ctx.ensure_object(dict).get("non_interactive")
    prompt_ok = not non_interactive and not _json_mode(ctx)

    console_obj = _console(ctx)
    doctor_payload = _doctor_payload("offline")

    saved: dict[str, Any] = {}
    errors: list[dict[str, str]] = []

    def _persist(key: str, value: str) -> None:
        try:
            set_key(key, value)
            saved[key] = value
        except (OSError, PermissionError, ValueError) as exc:
            errors.append({"key": key, "error": str(exc)})

    def _ask(key: str, label: str, current: str | None, flag_value: str | None) -> None:
        if flag_value is not None:
            _persist(key, flag_value)
            return
        if not prompt_ok:
            return
        default = current or ""
        answer = typer.prompt(label, default=default, show_default=bool(default))
        if answer and answer != current:
            _persist(key, str(answer))

    if not _json_mode(ctx):
        status = "[green]OK[/green]" if doctor_payload["ok"] else "[yellow]NEEDS ATTENTION[/yellow]"
        console_obj.print(
            Panel(
                f"Doctor (offline): {status}\n"
                f"Version: {__version__}\n\n"
                "This will save defaults so you can skip flags on future runs. "
                "Leave blank to skip a field. Nothing is sent anywhere.",
                title="ADAF-ATTACK init",
            )
        )
    existing = load_user_config()

    _ask(
        "workspace",
        "Default workspace directory",
        existing.get("workspace"),
        str(workspace) if workspace else None,
    )
    _ask(
        "target.domain",
        "Default authorized domain (blank to skip)",
        existing.get("target.domain"),
        domain,
    )
    _ask(
        "target.dc_ip",
        "Default DC IP or hostname (blank to skip)",
        existing.get("target.dc_ip"),
        dc_ip,
    )
    _ask(
        "target.username",
        "Default username (blank to skip)",
        existing.get("target.username"),
        username,
    )

    next_steps = [
        "adaf-attack list-capabilities --novice",
        "adaf-attack list-capabilities --novice --safe-only",
    ]
    if not skip_quickstart:
        next_steps.append("adaf-attack quickstart")
    next_steps.append("adaf-attack tour")

    payload = {
        "ok": doctor_payload["ok"] and not errors,
        "doctor_ok": doctor_payload["ok"],
        "saved": saved,
        "errors": errors,
        "next_steps": next_steps,
    }
    if _json_mode(ctx):
        _emit(ctx, payload, "")
        return

    if saved:
        console_obj.print("[bold]Saved defaults:[/bold]")
        for key, value in saved.items():
            console_obj.print(f"  {key} = {value}")
    else:
        console_obj.print("[dim]No defaults saved.[/dim]")
    if errors:
        console_obj.print("[yellow]Some values could not be saved:[/yellow]")
        for entry in errors:
            console_obj.print(f"  {entry['key']}: {entry['error']}")
    console_obj.print("\n[bold]Next:[/bold]")
    for step in next_steps:
        console_obj.print(f"  {step}")


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


if __name__ == "__main__":  # pragma: no cover - module CLI entry point
    app()
