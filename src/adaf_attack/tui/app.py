"""Interactive Textual application with runnable capabilities."""

from __future__ import annotations

import threading
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
from adaf_attack.core.runner import RunError, execute_capability
from adaf_attack.core.target import Target


class CapabilityItem(ListItem):  # type: ignore[misc]
    def __init__(self, cap_id: str, summary: str) -> None:
        super().__init__()
        self.cap_id = cap_id
        self.summary = summary

    def compose(self) -> ComposeResult:
        yield Label(f"[bold cyan]{self.cap_id}[/]  {self.summary}")


class ADAFAttackApp(App[None]):  # type: ignore[misc]
    CSS = """
    Screen { layout: vertical; }
    #sidebar { width: 42; border: solid $accent; padding: 0 1; }
    #main { border: solid $primary; }
    #target-form { height: auto; padding: 1; border-bottom: solid $accent; }
    #log-panel { height: 1fr; }
    #status { height: 3; border-top: solid $accent; padding: 0 1; }
    Input { margin-bottom: 1; }
    """

    TITLE = f"ADAF-ATTACK v{__version__}"
    SUB_TITLE = "Aggressive AD offensive toolkit — senior internal red team use"

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("r", "run_selected", "Run"),
        Binding("l", "list_caps", "Refresh"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.selected_cap: str | None = None
        self._running = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Static("[bold]Capabilities[/bold]", id="sidebar-title")
                yield ListView(id="cap-list")
            with Vertical(id="main"):
                with Vertical(id="target-form"):
                    yield Static("[bold]Target[/bold]")
                    yield Input(placeholder="Domain (corp.local)", id="domain")
                    yield Input(placeholder="DC IP / hostname", id="dc_ip")
                    yield Input(placeholder="Username (optional)", id="username")
                    yield Input(placeholder="Password (optional)", password=True, id="password")
                    yield Input(placeholder="Creds JSON file (optional rotation)", id="creds_file")
                    yield Input(
                        placeholder="ACL scope: high-value | domain", id="scope", value="high-value"
                    )
                    yield Input(placeholder="Attack-path start principal (optional)", id="start")
                    with Horizontal():
                        yield Label("Include secrets")
                        yield Switch(id="include_secrets", value=False)
                        yield Label("  Force")
                        yield Switch(id="force", value=False)
                    yield Button("Run selected capability", id="run-btn", variant="success")
                yield Log(id="log-panel", highlight=True, max_lines=2000)
        yield Static("Session: (none)  |  Target: (none)  |  Cap: (none)", id="status")
        yield Footer()

    def on_mount(self) -> None:
        self._populate_capabilities()
        self.query_one("#log-panel", Log).write(
            "[bold green]ADAF-ATTACK[/] ready.\n"
            "Set target fields, select a capability, then press Run (or 'r').\n"
            "[dim]No plan-only • No lab certification • No containment[/dim]"
        )

    def _populate_capabilities(self) -> None:
        import adaf_attack.capabilities  # noqa: F401
        from adaf_attack.core.registry import capability_registry

        list_view = self.query_one("#cap-list", ListView)
        list_view.clear()
        for cap in capability_registry.list():
            list_view.append(CapabilityItem(cap.id, cap.summary))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item = event.item
        if isinstance(item, CapabilityItem):
            self.selected_cap = item.cap_id
            self._update_status()

    def _update_status(self) -> None:
        domain = self.query_one("#domain", Input).value or "(none)"
        dc = self.query_one("#dc_ip", Input).value or ""
        target = f"{domain}" + (f" @ {dc}" if dc else "")
        cap = self.selected_cap or "(none)"
        self.query_one("#status", Static).update(
            f"Target: {target}  |  Cap: {cap}  |  {'RUNNING' if self._running else 'idle'}"
        )

    def action_list_caps(self) -> None:
        self._populate_capabilities()
        self.notify("Capabilities refreshed")

    def action_run_selected(self) -> None:
        self._start_run()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run-btn":
            self._start_run()

    def _start_run(self) -> None:
        if self._running:
            self.notify("Already running", severity="warning")
            return
        if not self.selected_cap:
            self.notify("Select a capability first", severity="warning")
            return

        domain = self.query_one("#domain", Input).value.strip()
        dc_ip = self.query_one("#dc_ip", Input).value.strip()
        if not domain or not dc_ip:
            self.notify("Domain and DC IP are required", severity="error")
            return

        username = self.query_one("#username", Input).value.strip() or None
        password = self.query_one("#password", Input).value or None
        creds_file = self.query_one("#creds_file", Input).value.strip() or None
        scope = self.query_one("#scope", Input).value.strip() or "high-value"
        start = self.query_one("#start", Input).value.strip() or None
        include_secrets = self.query_one("#include_secrets", Switch).value
        force = self.query_one("#force", Switch).value

        target = Target(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            password=password,
        )

        log = self.query_one("#log-panel", Log)
        log.write(f"\n[bold]→ {self.selected_cap}[/] on {domain} @ {dc_ip}")
        if creds_file:
            log.write(f"  creds-file={creds_file} (rotation)")
        self._running = True
        self._update_status()

        def worker() -> None:
            def log_fn(msg: str) -> None:
                self.call_from_thread(log.write, f"  {msg}")

            extra: dict[str, Any] = {"scope": scope}
            if start:
                extra["start"] = start
            try:
                out = execute_capability(
                    self.selected_cap,  # type: ignore[arg-type]
                    target,
                    force=force,
                    include_secrets=include_secrets,
                    creds_file=creds_file,
                    log=log_fn,
                    **extra,
                )
                interesting = out.get("interesting") or {}
                summary = out.get("graph_summary") or {}
                self.call_from_thread(
                    log.write,
                    f"[green]Done[/] session={out['session_id']}  "
                    f"nodes={summary.get('nodes', 0)} edges={summary.get('edges', 0)}",
                )
                top = interesting.get("top_paths") or []
                if top:
                    self.call_from_thread(log.write, "[bold]Top paths[/]")
                    for p in top[:5]:
                        short = " → ".join(x.split("@")[0] for x in p["path"][:5])
                        self.call_from_thread(log.write, f"  score={p['score']:>5}  {short}")
                self.call_from_thread(
                    self.notify, f"Completed {self.selected_cap}", severity="information"
                )
            except RunError as exc:
                self.call_from_thread(log.write, f"[red]Error:[/] {exc}")
                self.call_from_thread(self.notify, str(exc), severity="error")
            finally:
                self._running = False
                self.call_from_thread(self._update_status)

        threading.Thread(target=worker, daemon=True).start()


def run_tui() -> None:
    ADAFAttackApp().run()
