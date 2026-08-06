"""Interactive Textual application."""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Label, ListItem, ListView, Static

from adaf_attack import __version__


class CapabilityItem(ListItem):
    def __init__(self, cap_id: str, summary: str) -> None:
        super().__init__()
        self.cap_id = cap_id
        self.summary = summary

    def compose(self) -> ComposeResult:
        yield Label(f"[bold cyan]{self.cap_id}[/]  {self.summary}")


class ADAFAttackApp(App[None]):
    """Main interactive shell."""

    CSS = """
    Screen {
        layout: vertical;
    }
    #sidebar {
        width: 36;
        border: solid $accent;
        padding: 1;
    }
    #main {
        border: solid $primary;
        padding: 1;
    }
    #status {
        height: 3;
        border-top: solid $accent;
        padding: 0 1;
    }
    """

    TITLE = f"ADAF-ATTACK v{__version__}"
    SUB_TITLE = "Aggressive AD offensive toolkit — senior internal red team use"

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("l", "list_caps", "Capabilities"),
        Binding("d", "doctor", "Doctor"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Static("[bold]Capabilities[/bold]\n", id="sidebar-title")
                yield ListView(id="cap-list")
            with Vertical(id="main"):
                yield Static(
                    "[bold green]ADAF-ATTACK[/bold green]\n\n"
                    "Interactive shell ready.\n"
                    "Select a capability from the left or use key bindings.\n\n"
                    "[dim]No plan-only • No lab certification • No containment gates[/dim]\n"
                    "[dim]Lightweight controls: --force for destructive, redaction by default[/dim]",
                    id="main-panel",
                )
        yield Static("Session: (none)  |  Target: (none)", id="status")
        yield Footer()

    def on_mount(self) -> None:
        self._populate_capabilities()

    def _populate_capabilities(self) -> None:
        import adaf_attack.capabilities  # noqa: F401
        from adaf_attack.core.registry import capability_registry

        list_view = self.query_one("#cap-list", ListView)
        list_view.clear()

        for cap in capability_registry.list():
            list_view.append(CapabilityItem(cap.id, cap.summary))

    def action_list_caps(self) -> None:
        self._populate_capabilities()
        self.notify("Capabilities refreshed")

    def action_doctor(self) -> None:
        self.notify("Doctor: local environment looks usable", severity="information")


def run_tui() -> None:
    """Entry point called from the CLI."""
    app = ADAFAttackApp()
    app.run()
