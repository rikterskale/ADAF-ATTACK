"""Interactive Textual application with guided, review-first workflows."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    Log,
    Static,
    Switch,
)

from adaf_attack import __version__
from adaf_attack.core.capability_help_data import capability_option_spec
from adaf_attack.core.paths import default_workspace_dir
from adaf_attack.core.registry import Capability, capability_registry
from adaf_attack.core.runner import RunError, execute_capability
from adaf_attack.core.target import Target
from adaf_attack.core.user_config import load_user_config


class CapabilityItem(ListItem):  # type: ignore[misc,unused-ignore]
    def __init__(self, cap: Capability) -> None:
        super().__init__()
        self.cap_id = cap.id
        self.category = cap.category
        self.summary = cap.summary
        self.destructive = cap.destructive

    def compose(self) -> ComposeResult:
        risk = " [red]DESTRUCTIVE[/]" if self.destructive else ""
        yield Label(f"[bold cyan]{self.cap_id}[/]  [dim]{self.category}[/]{risk}\n  {self.summary}")


class ADAFAttackApp(App[None]):  # type: ignore[misc,unused-ignore]
    CSS = """
    Screen { layout: vertical; }
    #toolbar { height: auto; padding: 0 1; border-bottom: solid $accent; }
    #sidebar { width: 44; border: solid $accent; padding: 0 1; }
    #main { border: solid $primary; }
    #target-form { height: auto; padding: 1; border-bottom: solid $accent; }
    #log-panel { height: 1fr; }
    #status { height: 3; border-top: solid $accent; padding: 0 1; }
    #help-panel, #review-panel, #session-panel { height: auto; padding: 1; border-bottom: solid $accent; }
    #session-panel { max-height: 8; overflow-y: auto; }
    #search { margin-bottom: 1; }
    Input { margin-bottom: 1; }
    Button { margin-right: 1; }
    .section-label { color: $accent; text-style: bold; margin-top: 1; }
    """

    TITLE = f"ADAF-ATTACK v{__version__}"
    SUB_TITLE = "Authorized internal red team operations — review-first execution"

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("r", "run_selected", "Run"),
        Binding("v", "review_run", "Review"),
        Binding("d", "dry_run", "Dry run"),
        Binding("l", "list_caps", "Refresh"),
        Binding("s", "show_sessions", "Sessions"),
        Binding("p", "toggle_password", "Show/Hide password"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.selected_cap: str | None = None
        self._capability_running = False
        self._password_visible = False
        self._cancel_requested = threading.Event()
        self._capabilities: list[Capability] = []
        self._last_session: Path | None = None
        self._log_lines: list[str] = []

    def compose(self) -> ComposeResult:
        defaults = load_user_config()
        yield Header(show_clock=True)
        with Horizontal(id="toolbar"):
            yield Input(
                placeholder="Search capabilities by name, category, or keyword", id="search"
            )
            yield Button("Quickstart", id="quickstart-btn")
            yield Button("Sessions", id="sessions-btn")
            yield Button("Findings", id="findings-btn")
            yield Button("Copy findings", id="copy-btn")
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Static("[bold]Capabilities[/bold]", id="sidebar-title")
                yield ListView(id="cap-list")
                yield Static("Select one to see prerequisites and risk.", id="help-panel")
            with Vertical(id="main"):
                with Vertical(id="target-form"):
                    yield Static("[bold]Target & credentials[/bold]", classes="section-label")
                    yield Input(
                        placeholder="Domain (corp.local)",
                        id="domain",
                        value=defaults.get("target.domain", ""),
                    )
                    yield Input(
                        placeholder="DC IP / hostname",
                        id="dc_ip",
                        value=defaults.get("target.dc_ip", ""),
                    )
                    yield Input(
                        placeholder="Username (optional)",
                        id="username",
                        value=defaults.get("target.username", ""),
                    )
                    with Horizontal():
                        yield Input(placeholder="Password (optional)", password=True, id="password")
                        yield Button("Show", id="toggle-password-btn")
                    yield Input(placeholder="NT / LM:NT hash (optional)", id="hashes")
                    yield Input(placeholder="AES key hex (optional)", id="aes_key")
                    yield Input(placeholder="Kerberos ccache path (optional)", id="ccache")
                    yield Input(placeholder="Creds JSON file (optional rotation)", id="creds_file")
                    yield Static("[bold]Scope & safety[/bold]", classes="section-label")
                    yield Input(
                        placeholder="ACL scope: high-value | domain",
                        id="scope",
                        value=defaults.get("acl.scope", "high-value"),
                    )
                    yield Input(placeholder="Attack-path start principal (optional)", id="start")
                    with Horizontal():
                        yield Label("Kerberos")
                        yield Switch(id="kerberos", value=bool(defaults.get("target.kerberos")))
                        yield Label("  LDAPS")
                        yield Switch(id="ldaps", value=bool(defaults.get("target.ldaps")))
                        yield Label("  Include secrets")
                        yield Switch(id="include_secrets", value=False)
                        yield Label("  Force")
                        yield Switch(id="force", value=False)
                    with Horizontal():
                        yield Button("Review", id="review-btn")
                        yield Button("Dry run", id="dry-run-btn")
                        yield Button("Run selected", id="run-btn", variant="success")
                        yield Button("Cancel", id="cancel-btn", variant="error", disabled=True)
                yield Static(
                    "Select a capability and choose Review before execution.", id="review-panel"
                )
                yield Static("No session loaded.", id="session-panel")
                with Horizontal():
                    yield Input(placeholder="Filter logs by text or severity", id="log-filter")
                yield Log(id="log-panel", highlight=True, max_lines=2000)
        yield Static("Session: (none)  |  Target: (none)  |  Cap: (none)  |  idle", id="status")
        yield Footer()

    def on_mount(self) -> None:
        self._populate_capabilities()
        self._show_log("[bold green]ADAF-ATTACK[/] ready. Use Quickstart or search capabilities.")
        if not self.query_one("#domain", Input).value:
            self.notify(
                "First run: Quickstart will focus the required target fields.",
                severity="information",
            )
            self.query_one("#domain", Input).focus()

    def _show_log(self, message: str) -> None:
        self._log_lines.extend(message.splitlines())
        self._refresh_log()

    def _refresh_log(self) -> None:
        needle = self.query_one("#log-filter", Input).value.strip().lower()
        log = self.query_one("#log-panel", Log)
        log.clear()
        for line in self._log_lines:
            if not needle or needle in line.lower():
                log.write(line)

    def _write_run_log(self, message: str) -> None:
        self.call_from_thread(self._show_log, message)

    def _populate_capabilities(self, query: str = "") -> None:
        import adaf_attack.capabilities  # noqa: F401

        self._capabilities = capability_registry.list()
        needle = query.strip().lower()
        visible = [
            cap
            for cap in self._capabilities
            if not needle
            or needle in f"{cap.id} {cap.category} {cap.summary} {' '.join(cap.tags)}".lower()
        ]
        list_view = self.query_one("#cap-list", ListView)
        list_view.clear()
        for cap in visible:
            list_view.append(CapabilityItem(cap))
        self.query_one("#sidebar-title", Static).update(
            f"[bold]Capabilities[/bold] ({len(visible)}/{len(self._capabilities)})"
        )

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search":
            self._populate_capabilities(event.value)
        elif event.input.id == "log-filter":
            self._refresh_log()
        elif event.input.id in {"domain", "dc_ip"}:
            self._update_status()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, CapabilityItem):
            self.selected_cap = event.item.cap_id
            self._update_status()
            self._update_help()

    def _selected(self) -> Capability | None:
        return capability_registry.get(self.selected_cap) if self.selected_cap else None

    def _update_help(self) -> None:
        cap = self._selected()
        if not cap:
            return
        spec = capability_option_spec(cap.id, cap.destructive)
        required = ", ".join(spec.required) or "none (offline/session input)"
        optional = ", ".join(spec.optional[:6]) or "none"
        notes = f"\n[italic]{spec.notes}[/]" if spec.notes else ""
        self.query_one("#help-panel", Static).update(
            f"[bold]{cap.id}[/]\n{cap.summary}\nCategory: {cap.category}\n"
            f"Required: {required}\nOptional: {optional}{notes}"
        )

    def _update_status(self) -> None:
        domain = self.query_one("#domain", Input).value or "(none)"
        dc = self.query_one("#dc_ip", Input).value or ""
        target = f"{domain}" + (f" @ {dc}" if dc else "")
        cap = self.selected_cap or "(none)"
        state = "RUNNING" if self._capability_running else "idle"
        self.query_one("#status", Static).update(f"Target: {target}  |  Cap: {cap}  |  {state}")

    def action_list_caps(self) -> None:
        self._populate_capabilities(self.query_one("#search", Input).value)
        self.notify("Capabilities refreshed")

    def action_run_selected(self) -> None:
        self._start_run()

    def action_review_run(self) -> None:
        self._review_run()

    def action_dry_run(self) -> None:
        self._dry_run()

    def action_show_sessions(self) -> None:
        self._show_sessions()

    def action_toggle_password(self) -> None:
        self._toggle_password()

    def _toggle_password(self) -> None:
        pw = self.query_one("#password", Input)
        self._password_visible = not self._password_visible
        pw.password = not self._password_visible
        self.query_one("#toggle-password-btn", Button).label = (
            "Hide" if self._password_visible else "Show"
        )

    def _validate_target(self) -> tuple[str, str] | None:
        domain = self.query_one("#domain", Input).value.strip()
        dc_ip = self.query_one("#dc_ip", Input).value.strip()
        if not domain:
            self.notify("Domain and DC IP are required", severity="error")
            self.query_one("#domain", Input).focus()
            return None
        if not dc_ip:
            self.notify("Domain and DC IP are required", severity="error")
            self.query_one("#dc_ip", Input).focus()
            return None
        if any(ch.isspace() for ch in dc_ip):
            self.notify("DC IP / hostname cannot contain spaces.", severity="error")
            return None
        hashes = self.query_one("#hashes", Input).value.strip()
        if hashes and ":" not in hashes and len(hashes) not in {32, 64}:
            self.notify(
                "Hashes must be LM:NT, an NT hash, or a 64-character AES value.", severity="error"
            )
            self.query_one("#hashes", Input).focus()
            return None
        creds_file = self.query_one("#creds_file", Input).value.strip()
        if creds_file and not Path(creds_file).expanduser().is_file():
            self.notify(f"Credential file not found: {creds_file}", severity="error")
            self.query_one("#creds_file", Input).focus()
            return None
        return domain, dc_ip

    def _review_run(self) -> None:
        cap = self._selected()
        target = self._validate_target() if cap else None
        if not cap:
            self.notify("Select a capability first.", severity="warning")
            return
        if target is None:
            return
        spec = capability_option_spec(cap.id, cap.destructive)
        force = self.query_one("#force", Switch).value
        risk = (
            "DESTRUCTIVE — Force is enabled."
            if cap.destructive and force
            else "DESTRUCTIVE — Force is required."
            if cap.destructive
            else "Read-only / non-destructive"
        )
        self.query_one("#review-panel", Static).update(
            f"[bold]Execution review[/bold]  {cap.id}\n"
            f"Target: {target[0]} @ {target[1]}\nCategory: {cap.category}  |  Risk: {risk}\n"
            f"Required contract: {', '.join(spec.required) or 'session/workspace input'}\n"
            "Confirm the scope above, then press Run selected."
        )
        if cap.destructive and not force:
            self.notify(
                "Review shows a destructive capability; enable Force only when authorized.",
                severity="warning",
            )

    def _dry_run(self) -> None:
        cap = self._selected()
        if not cap:
            self.notify("Select a capability first.", severity="warning")
            return
        spec = capability_option_spec(cap.id, cap.destructive)
        self._review_run()
        self._show_log(
            f"[yellow]DRY RUN[/] {cap.id}: no network action started.\n"
            f"Required: {', '.join(spec.required) or 'workspace/session'}\n"
            f"Optional: {', '.join(spec.optional) or 'none'}"
        )

    def _quickstart(self) -> None:
        self.query_one("#domain", Input).focus()
        self.query_one("#review-panel", Static).update(
            "[bold]Quickstart[/bold]\n1. Enter domain and DC IP.\n"
            "2. Select a capability and review prerequisites.\n"
            "3. Use Dry run, then Review and Run when authorized."
        )

    def _start_run(self) -> None:
        if self._capability_running:
            self.notify("Already running", severity="warning")
            return
        if not self.selected_cap:
            self.notify("Select a capability first", severity="warning")
            return
        capability_id = self.selected_cap
        target_values = self._validate_target()
        if target_values is None:
            return
        domain, dc_ip = target_values
        username = self.query_one("#username", Input).value.strip() or None
        password = self.query_one("#password", Input).value or None
        hashes = self.query_one("#hashes", Input).value.strip() or None
        aes_key = self.query_one("#aes_key", Input).value.strip() or None
        ccache = self.query_one("#ccache", Input).value.strip() or None
        creds_file = self.query_one("#creds_file", Input).value.strip() or None
        scope = self.query_one("#scope", Input).value.strip() or "high-value"
        start = self.query_one("#start", Input).value.strip() or None
        include_secrets = self.query_one("#include_secrets", Switch).value
        force = self.query_one("#force", Switch).value
        kerberos = self.query_one("#kerberos", Switch).value
        ldaps = self.query_one("#ldaps", Switch).value
        target = Target(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            password=password,
            hashes=hashes,
            aes_key=aes_key,
            ccache=ccache,
            use_kerberos=kerberos,
            ldaps=ldaps,
        )
        self._show_log(f"\n[bold]→ {capability_id}[/] on {domain} @ {dc_ip}")
        self._cancel_requested.clear()
        self._capability_running = True
        self.query_one("#cancel-btn", Button).disabled = False
        self._update_status()

        def worker() -> None:
            def log_fn(msg: str) -> None:
                self._write_run_log(f"  {msg}")
                if self._cancel_requested.is_set():
                    self._write_run_log(
                        "[yellow]Cancellation requested; stopping at the next safe boundary.[/]"
                    )

            extra: dict[str, Any] = {"scope": scope}
            if start:
                extra["start"] = start
            try:
                out = execute_capability(
                    capability_id,
                    target,
                    force=force,
                    include_secrets=include_secrets,
                    creds_file=creds_file,
                    log=log_fn,
                    workspace=default_workspace_dir(),
                    **extra,
                )
                self._last_session = Path(out["session_path"])
                summary = out.get("graph_summary") or {}
                self._write_run_log(
                    f"[green]Done[/] session={out['session_id']}  nodes={summary.get('nodes', 0)} edges={summary.get('edges', 0)}"
                )
                self.call_from_thread(self._load_findings, Path(out["session_path"]))
                self.call_from_thread(
                    self.notify,
                    f"Completed {capability_id}; session ready",
                    severity="information",
                )
            except RunError as exc:
                self._write_run_log(
                    f"[red]Error:[/] {exc}\n[dim]Check the review panel and capability prerequisites.[/]"
                )
                self.call_from_thread(self.notify, str(exc), severity="error")
            finally:
                self._capability_running = False
                self.call_from_thread(
                    self.query_one("#cancel-btn", Button).__setattr__, "disabled", True
                )
                self.call_from_thread(self._update_status)

        threading.Thread(target=worker, daemon=True).start()

    def _cancel(self) -> None:
        if self._capability_running:
            self._cancel_requested.set()
            self.notify(
                "Cancellation requested; the active runner will finish its safe boundary.",
                severity="warning",
            )

    def _show_sessions(self) -> None:
        workspace = default_workspace_dir()
        rows: list[str] = []
        if workspace.exists():
            for session in sorted(workspace.iterdir(), reverse=True):
                if not session.is_dir() or not (session / "session.json").exists():
                    continue
                meta = self._read_json(session / "session.json")
                rows.append(
                    f"{meta.get('session_id', session.name)}  {meta.get('created_at', '')[:19]}  {session}"
                )
        self.query_one("#session-panel", Static).update(
            "[bold]Recent sessions[/bold]\n" + ("\n".join(rows[:8]) or "No sessions found.")
        )

    def _show_findings(self) -> None:
        if self._last_session:
            self._load_findings(self._last_session)
        else:
            self.query_one("#session-panel", Static).update(
                "[bold]Findings dashboard[/bold]\nRun a capability or select a session first."
            )

    def _copy_findings(self) -> None:
        text = str(self.query_one("#session-panel", Static).render())
        try:
            self.copy_to_clipboard(text)
            self.notify("Findings dashboard copied to clipboard.", severity="information")
        except Exception:  # noqa: BLE001
            self.notify("Clipboard is unavailable in this terminal.", severity="warning")

    def _load_findings(self, session: Path) -> None:
        interesting = self._read_json(session / "interesting.json")
        graph = self._read_json(session / "graph.json")
        findings = self._read_json(session / "findings.json")
        top_paths = interesting.get("top_paths") or []
        severity_counts: dict[str, int] = {}
        for item in (
            findings.get("findings", []) if isinstance(findings.get("findings"), list) else []
        ):
            severity = (
                str(item.get("severity", "unknown")).lower()
                if isinstance(item, dict)
                else "unknown"
            )
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        summary = graph.get("summary", graph) if isinstance(graph, dict) else {}
        path_lines = [
            "  " + " → ".join(str(x).split("@")[0] for x in path.get("path", [])[:5])
            for path in top_paths[:3]
            if isinstance(path, dict)
        ]
        self.query_one("#session-panel", Static).update(
            f"[bold]Findings dashboard[/bold]  {session.name}\n"
            f"Nodes: {summary.get('nodes', 0)}  Edges: {summary.get('edges', 0)}  "
            f"Findings: {sum(severity_counts.values())}  Severity: {severity_counts or 'none'}\n"
            + ("Top paths:\n" + "\n".join(path_lines) if path_lines else "No top paths recorded.")
        )

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def on_button_pressed(self, event: Button.Pressed) -> None:
        actions = {
            "run-btn": self._start_run,
            "review-btn": self._review_run,
            "dry-run-btn": self._dry_run,
            "cancel-btn": self._cancel,
            "quickstart-btn": self._quickstart,
            "sessions-btn": self._show_sessions,
            "findings-btn": self._show_findings,
            "copy-btn": self._copy_findings,
            "toggle-password-btn": self._toggle_password,
        }
        action = actions.get(event.button.id or "")
        if action:
            action()


def run_tui() -> None:
    ADAFAttackApp().run()
