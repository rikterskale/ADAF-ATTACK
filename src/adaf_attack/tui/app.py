"""Interactive Textual application with guided, review-first workflows."""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import threading
from contextlib import suppress
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Button,
    Checkbox,
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
from adaf_attack.core.control_plane import package_evidence
from adaf_attack.core.engagement_dashboard import inspect_edge
from adaf_attack.core.novice import (
    beginner_next_actions,
    capability_difficulty,
    explain_finding,
    glossary_definition,
    home_actions,
    plain_description,
    safety_summary,
)
from adaf_attack.core.paths import default_workspace_dir
from adaf_attack.core.profiles import active_opsec, get_profile, list_profiles, set_profile
from adaf_attack.core.registry import Capability, capability_registry
from adaf_attack.core.reporting import generate_report_bundle
from adaf_attack.core.runner import RunError, execute_capability
from adaf_attack.core.standout_ux import copilot_recommendations, evidence_cockpit, session_timeline
from adaf_attack.core.tooling import graph_explorer
from adaf_attack.core.target import Target
from adaf_attack.core.user_config import (
    favorite_capabilities,
    load_user_config,
    recent_capabilities,
    recent_targets,
    record_recent_capability,
    record_recent_target,
    save_user_config,
    set_favorite_capability,
)
from adaf_attack.core.ux import (
    build_ready_command,
    format_stages_progress,
    group_capabilities_by_phase,
    risk_checklist,
    session_findings_dashboard,
    suggested_next_actions,
)
from adaf_attack.core.workflow_engine import WorkflowEngine, finding_from_document


class CapabilityItem(ListItem):  # type: ignore[misc,unused-ignore]
    def __init__(self, cap: Capability, phase_header: str | None = None) -> None:
        super().__init__()
        self.cap_id = cap.id
        self.category = cap.category
        self.summary = cap.summary
        self.destructive = cap.destructive
        self.phase_header = phase_header

    def compose(self) -> ComposeResult:
        risk = " [red]DESTRUCTIVE[/]" if self.destructive else ""
        safety = safety_summary(
            Capability(self.cap_id, self.summary, self.destructive, self.category)
        )
        if self.phase_header:
            yield Label(f"[bold yellow]{self.phase_header}[/]")
        yield Label(
            f"[bold cyan]{self.cap_id}[/]  [dim]{self.category}[/] [{safety['level']}]{risk}\n"
            f"  {self.summary}"
        )


class AttackEdgeItem(ListItem):  # type: ignore[misc,unused-ignore]
    """Selectable saved graph edge for the read-only attack-path workspace."""

    def __init__(self, edge: dict[str, Any]) -> None:
        super().__init__()
        self.edge = edge

    def compose(self) -> ComposeResult:
        yield Label(
            f"[bold cyan]{self.edge.get('relation', 'unknown')}[/]  "
            f"{self.edge.get('source', '?')} → {self.edge.get('target', '?')}"
        )


class ADAFAttackApp(App[None]):  # type: ignore[misc,unused-ignore]
    CSS = """
    Screen { layout: vertical; }
    #toolbar { height: auto; padding: 0 1; border-bottom: solid $accent; }
    #sidebar { width: 44; border: solid $accent; padding: 0 1; }
    #main { border: solid $primary; }
    #target-form { height: auto; padding: 1; border-bottom: solid $accent; }
    #log-panel { height: 1fr; }
    #status, #progress, #credential-strip { height: auto; border-top: solid $accent; padding: 0 1; }
    #help-panel, #review-panel, #session-panel, #attack-path-panel, #engagement-dashboard, #first-launch-panel { height: auto; padding: 1; border-bottom: solid $accent; }
    #wizard-panel { height: auto; padding: 1; border: solid $success; margin-bottom: 1; }
    #wizard-step { color: $success; text-style: bold; }
    #wizard-actions { height: auto; margin-top: 1; }
    #readiness, #target-validation, #recommendations-panel, #summary-panel { height: auto; padding: 0 1; }
    #template-panel { height: auto; padding: 1; border-bottom: solid $accent; }
    #session-panel { max-height: 8; overflow-y: auto; }
    #search { margin-bottom: 1; }
    Input { margin-bottom: 1; }
    Button { margin-right: 1; }
    .section-label, .phase-label { color: $accent; text-style: bold; margin-top: 1; }
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
        Binding("ctrl+k", "focus_search", "Search", priority=True),
        Binding("e", "jump_to_error", "Last error"),
        Binding("u", "undo_form_reset", "Undo reset"),
        Binding("?", "show_cheat_sheet", "Key help"),
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
        self._reviewed_cap: str | None = None
        self._active_stage: str | None = None
        self._safe_mode = bool(load_user_config().get("novice.safe_mode", True))
        self._green_only = False
        self._advanced_credentials_visible = False
        self._form_snapshot: dict[str, Any] | None = None
        self._wizard_step = 0
        self._pause_requested = threading.Event()
        self._wizard_resume_available = False
        self._workflow: WorkflowEngine | None = None
        self._selected_attack_edge: dict[str, Any] | None = None

    def compose(self) -> ComposeResult:
        defaults = load_user_config()
        yield Header(show_clock=True)
        with Horizontal(id="toolbar"):
            yield Input(
                placeholder="Search capabilities by name, category, or keyword", id="search"
            )
            yield Button("Quickstart", id="quickstart-btn")
            yield Button("What should I do?", id="home-btn")
            yield Button("Explain selected", id="explain-selected-btn")
            yield Button("What next?", id="what-next-btn")
            yield Button("Setup", id="setup-btn")
            yield Switch(value=self._safe_mode, id="beginner-mode")
            yield Label("Beginner mode")
            yield Switch(value=self._green_only, id="green-only")
            yield Label("Offline-safe only")
            yield Button("Reset form", id="reset-form-btn")
            yield Button("Undo reset", id="undo-reset-btn", disabled=True)
            yield Button("Sessions", id="sessions-btn")
            yield Button("Findings", id="findings-btn")
            yield Button("Cockpit", id="cockpit-btn")
            yield Button("Attack paths", id="attack-paths-btn")
            yield Button("Timeline", id="timeline-btn")
            yield Button("Copilot", id="copilot-btn")
            yield Button("Copy findings", id="copy-btn")
            yield Button("Copy ready command", id="copy-command-btn")
            yield Button("Command only", id="command-only-btn")
            yield Button("Pin selected", id="pin-selected-btn", disabled=True)
            yield Button("Use latest target", id="use-latest-target-btn")
        yield Static(
            "[bold]Engagement dashboard[/bold]\nLoading current engagement state.",
            id="engagement-dashboard",
        )
        yield Static(
            "[bold]First-launch setup[/bold]\nChecking local defaults.", id="first-launch-panel"
        )
        with Vertical(id="wizard-panel"):
            yield Static("Guided workflow", id="wizard-step")
            yield Static("", id="wizard-guide")
            with Horizontal(id="wizard-actions"):
                yield Button("Back", id="wizard-back", disabled=True)
                yield Button("Next", id="wizard-next", variant="primary")
                yield Button("Start over", id="wizard-start-over")
                yield Button("Pause", id="pause-btn", disabled=True)
                yield Button("Create reports", id="reports-btn", disabled=True)
                yield Button("Package evidence", id="package-btn", disabled=True)
            yield Static("Readiness: 0/100", id="readiness")
            yield Static("", id="target-validation")
            yield Static("", id="recommendations-panel")
            yield Static("", id="summary-panel")
            yield Static("Workflow state: initializing", id="workflow-state-panel")
        with Horizontal(id="template-panel"):
            yield Label("Start with a workflow: ")
            yield Button("Safe reconnaissance", id="template-recon")
            yield Button("AD CS review", id="template-adcs")
            yield Button("Full assessment", id="template-full")
            yield Button("I'm not sure", id="template-help")
            yield Button("Resume saved", id="resume-btn", disabled=True)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Static("[bold]Capabilities[/bold]", id="sidebar-title")
                yield Static(
                    "[green]GREEN[/green] offline-safe  ·  "
                    "[yellow]YELLOW[/yellow] reads live target  ·  "
                    "[red]RED[/red] can modify target",
                    id="safety-legend",
                )
                yield ListView(id="cap-list")
                yield Static("Select one to see prerequisites and risk.", id="help-panel")
            with Vertical(id="main"):
                with Vertical(id="target-form"):
                    yield Static("[bold]Target & credentials[/bold]", classes="section-label")
                    with Horizontal():
                        yield Input(placeholder="Profile name", id="profile-name")
                        yield Button("Load profile", id="load-profile-btn")
                        yield Button("Save profile", id="save-profile-btn")
                        yield Button("Set default", id="default-profile-btn")
                    yield Static(
                        "Safe Mode: nothing changes until Force is enabled.", id="novice-panel"
                    )
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
                    yield Button("Advanced credentials", id="advanced-creds-btn")
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
                    yield Static("Credential material: none", id="credential-strip")
                yield Static(
                    "Select a capability and choose Review before execution.", id="review-panel"
                )
                with Vertical(id="checklist-panel"):
                    yield Static("[bold]Review checklist[/bold]", classes="section-label")
                    for item in ("scope", "auth", "force", "opsec", "rollback"):
                        yield Checkbox(item, id=f"check-{item}")
                    yield Button("Acknowledge review", id="ack-review-btn")
                yield Static("No session loaded.", id="session-panel")
                yield Static(
                    "[bold]Attack-path workspace[/bold]\nSelect Attack paths to inspect saved graph routes.",
                    id="attack-path-panel",
                )
                yield ListView(id="attack-edge-list")
                yield Static(
                    "Select an observed edge to inspect evidence, risk, ATT&CK mapping, and remediation.",
                    id="attack-edge-detail",
                )
                yield Button("Prepare validation review", id="prepare-edge-btn", disabled=True)
                with Horizontal():
                    yield Input(placeholder="Filter logs by text or severity", id="log-filter")
                yield Log(id="log-panel", highlight=True, max_lines=2000)
        yield Static("Session: (none)  |  Target: (none)  |  Cap: (none)  |  idle", id="status")
        yield Static(
            "Stages: prepare → connect → execute → harvest/analyze → next-actions", id="progress"
        )
        yield Footer()

    def on_mount(self) -> None:
        self._populate_capabilities()
        self._refresh_profile_hint()
        self._refresh_pin_button()
        self._update_credential_strip()
        self._set_advanced_credentials_visible(False)
        self._apply_beginner_mode(self._safe_mode)
        self._set_wizard_step(0, persist=False)
        self._load_wizard_resume()
        self._update_readiness()
        self._refresh_first_launch_panel()
        self._update_engagement_dashboard()
        self._refresh_pin_button()
        self._workflow = WorkflowEngine(default_workspace_dir())
        self._refresh_workflow_panel()
        self._update_engagement_dashboard()
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
        self.call_from_thread(self._update_progress)

    def _populate_capabilities(self, query: str = "") -> None:
        import adaf_attack.capabilities  # noqa: F401

        self._capabilities = capability_registry.list()
        needle = query.strip().lower()

        def _matches(cap: Capability) -> bool:
            if needle and needle not in (
                f"{cap.id} {cap.category} {cap.summary} {' '.join(cap.tags)}".lower()
            ):
                return False
            return not (self._green_only and safety_summary(cap)["level"] != "GREEN")

        visible = [cap for cap in self._capabilities if _matches(cap)]
        list_view = self.query_one("#cap-list", ListView)
        list_view.clear()
        visible_ids = {cap.id for cap in visible}
        for phase, caps in group_capabilities_by_phase().items():
            phase_caps = [cap for cap in caps if cap.id in visible_ids]
            if not phase_caps:
                continue
            for index, cap in enumerate(phase_caps):
                header = (
                    f"{phase.replace('-', ' ').title()} ({len(phase_caps)})" if index == 0 else None
                )
                list_view.append(CapabilityItem(cap, header))
        self.query_one("#sidebar-title", Static).update(
            f"[bold]Capabilities[/bold] ({len(visible)}/{len(self._capabilities)})"
        )

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search":
            self._populate_capabilities(event.value)
        elif event.input.id == "log-filter":
            self._refresh_log()
        elif event.input.id in {"domain", "dc_ip", "scope"}:
            self._update_status()
            self._update_readiness()
            self._validate_target_inline()
            self._update_engagement_dashboard()
            self._refresh_first_launch_panel()
        elif event.input.id in {"username", "password", "hashes", "aes_key", "ccache"}:
            self._update_credential_strip()
            self._update_readiness()
            self._refresh_first_launch_panel()

    def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id == "force":
            self._reviewed_cap = None
            self._update_run_gate()
        elif event.switch.id == "beginner-mode":
            self._apply_beginner_mode(event.value)
        elif event.switch.id == "green-only":
            self._green_only = bool(event.value)
            self._populate_capabilities(self.query_one("#search", Input).value)
        self._update_readiness()

    def on_checkbox_changed(self, _event: Checkbox.Changed) -> None:
        self._reviewed_cap = None
        self._update_run_gate()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, CapabilityItem):
            self.selected_cap = event.item.cap_id
            record_recent_capability(event.item.cap_id)
            self._reviewed_cap = None
            self._update_status()
            self._update_help()
            self._update_run_gate()
            self._update_readiness()
            self._update_engagement_dashboard()
            if self._wizard_step < 2:
                self._set_wizard_step(2)
        elif isinstance(event.item, AttackEdgeItem):
            self._show_attack_edge(event.item.edge)

    def _apply_beginner_mode(self, enabled: bool) -> None:
        """Hide optional controls; execution safety requirements remain unchanged."""
        self._safe_mode = enabled
        config = load_user_config()
        config["novice.safe_mode"] = enabled
        with suppress(OSError, PermissionError):
            save_user_config(config)
        # Managed workstations may expose a read-only profile directory. The
        # setting still applies for this process.
        for widget_id in (
            "advanced-creds-btn",
            "scope",
            "start",
            "kerberos",
            "ldaps",
            "include_secrets",
        ):
            self.query_one(f"#{widget_id}").display = not enabled
        if enabled:
            self._set_advanced_credentials_visible(False)
        self.query_one("#novice-panel", Static).update(
            "Beginner Mode: essential fields only; advanced controls stay hidden."
            if enabled
            else "Advanced Mode: optional credentials and targeting controls are available."
        )

    def _set_wizard_step(self, step: int, *, persist: bool = True) -> None:
        """Move the operator through one predictable, review-first workflow."""
        self._wizard_step = max(0, min(step, 5))
        steps = (
            (
                "1 of 5 · Target",
                "Start with the authorized domain and domain controller. These are the only required values for the first step.",
            ),
            (
                "2 of 5 · Access",
                "Add the least-privileged credentials or session material available. Leave optional fields empty when you are using an existing session.",
            ),
            (
                "3 of 5 · Objective",
                "Choose one capability. The sidebar is grouped by phase and every capability shows its prerequisites and safety level.",
            ),
            (
                "4 of 5 · Review",
                "Review scope, authentication, OPSEC, rollback, and force requirements. Nothing executes until the review is acknowledged.",
            ),
            (
                "5 of 5 · Run & learn",
                "Run, watch the staged progress, then use the findings dashboard and suggested next action to continue the engagement.",
            ),
            (
                "Complete · Findings",
                "This session is complete. Inspect findings, copy the evidence summary, or start the next guided action.",
            ),
        )
        title, guide = steps[self._wizard_step]
        self.query_one("#wizard-step", Static).update(title)
        self.query_one("#wizard-guide", Static).update(guide)
        back = self.query_one("#wizard-back", Button)
        next_button = self.query_one("#wizard-next", Button)
        back.disabled = self._wizard_step == 0 or self._capability_running
        next_button.disabled = self._capability_running
        next_button.label = (
            "Continue to access"
            if self._wizard_step == 0
            else "Continue to objective"
            if self._wizard_step == 1
            else "Review objective"
            if self._wizard_step == 2
            else "Continue to run"
            if self._wizard_step == 3
            else "Run selected"
            if self._wizard_step == 4
            else "Start another"
        )
        self.query_one("#wizard-start-over", Button).disabled = self._capability_running
        if persist:
            self._save_wizard_state()

    def _save_wizard_state(self) -> None:
        """Persist non-secret wizard state so an interrupted workflow can resume."""
        try:
            config = load_user_config()
            config["ui.wizard_state"] = {
                "step": self._wizard_step,
                "selected_cap": self.selected_cap,
                "domain": self.query_one("#domain", Input).value.strip(),
                "dc_ip": self.query_one("#dc_ip", Input).value.strip(),
                "username": self.query_one("#username", Input).value.strip(),
                "scope": self.query_one("#scope", Input).value.strip(),
            }
            save_user_config(config)
        except (OSError, PermissionError):
            # A locked-down operator workstation should not prevent execution.
            return

    def _load_wizard_resume(self) -> None:
        try:
            state = load_user_config().get("ui.wizard_state") or {}
        except (OSError, PermissionError):
            state = {}
        if not isinstance(state, dict) or not any(
            state.get(key) for key in ("domain", "dc_ip", "selected_cap")
        ):
            return
        self._wizard_resume_available = True
        self.query_one("#resume-btn", Button).disabled = False

    def _resume_wizard(self) -> None:
        try:
            state = load_user_config().get("ui.wizard_state") or {}
        except (OSError, PermissionError):
            state = {}
        if not isinstance(state, dict):
            return
        for key in ("domain", "dc_ip", "username", "scope"):
            if state.get(key) is not None:
                self.query_one(f"#{key}", Input).value = str(state[key])
        selected = str(state.get("selected_cap") or "")
        if selected and capability_registry.get(selected):
            self.selected_cap = selected
            self._update_help()
        try:
            step = int(state.get("step", 0))
        except (TypeError, ValueError):
            step = 0
            self.notify(
                "Saved workflow step was invalid; restarted at the first step.",
                severity="warning",
            )
        self._set_wizard_step(step)
        self._update_readiness()
        self.notify(
            "Saved workflow restored. Review the target and continue when ready.",
            severity="information",
        )

    def _update_readiness(self) -> None:
        checks = (
            bool(self.query_one("#domain", Input).value.strip()),
            bool(self.query_one("#dc_ip", Input).value.strip()),
            bool(
                self.query_one("#username", Input).value.strip()
                or self.query_one("#ccache", Input).value.strip()
                or self.query_one("#password", Input).value
            ),
            bool(self.selected_cap),
            bool(self._reviewed_cap == self.selected_cap),
        )
        score = sum(
            value * weight for value, weight in zip(checks, (20, 20, 20, 20, 20), strict=True)
        )
        missing = [
            label
            for value, label in zip(
                checks, ("domain", "DC", "access", "objective", "review"), strict=True
            )
            if not value
        ]
        text = f"Readiness: {score}/100"
        if missing:
            text += f" · Next: {missing[0]}"
        else:
            text += " · Ready to run"
        self.query_one("#readiness", Static).update(text)

    def _validate_target_inline(self) -> None:
        domain = self.query_one("#domain", Input).value.strip()
        dc_ip = self.query_one("#dc_ip", Input).value.strip()
        if not domain:
            message = "Domain is required: enter the authorized AD DNS name, such as corp.example."
        elif any(char.isspace() for char in domain) or "/" in domain:
            message = "Domain looks invalid: use a DNS name without spaces or a URL path."
        elif not dc_ip:
            message = "DC address is required: enter an IP address or resolvable DC hostname."
        elif any(char.isspace() for char in dc_ip) or "/" in dc_ip:
            message = "DC address looks invalid: use an IP or hostname, not a URL."
        else:
            try:
                ipaddress.ip_address(dc_ip)
                message = (
                    "Target format looks ready. Reachability will be checked during doctor/run."
                )
            except ValueError:
                if "." not in dc_ip and dc_ip.lower() not in {"localhost", "dc"}:
                    message = (
                        "DC address looks unusual: use a dotted IP or fully qualified hostname."
                    )
                else:
                    message = (
                        "Target format looks ready. Reachability will be checked during doctor/run."
                    )
        self.query_one("#target-validation", Static).update(message)

    def _refresh_first_launch_panel(self) -> None:
        try:
            domain = bool(self.query_one("#domain", Input).value.strip())
            dc_ip = bool(self.query_one("#dc_ip", Input).value.strip())
            access = bool(
                self.query_one("#username", Input).value.strip()
                or self.query_one("#ccache", Input).value.strip()
                or self.query_one("#password", Input).value
            )
        except Exception:  # noqa: BLE001
            # A minimal/test screen may not mount the setup controls.
            return
        profile_count = len(list_profiles())
        checklist = [
            ("workspace", default_workspace_dir().exists()),
            ("target", domain and dc_ip),
            ("access", access),
            ("profile", profile_count > 0),
            ("quickstart", self._last_session is not None),
        ]
        done = sum(1 for _label, ok in checklist if ok)
        next_item = next((label for label, ok in checklist if not ok), "review")
        lines = [
            f"Setup readiness: {done}/{len(checklist)}",
            f"Next: {next_item}",
            "Use Setup for first-run defaults or What should I do? for goal-based commands.",
        ]
        try:
            self.query_one("#first-launch-panel", Static).update(
                "[bold]First-launch setup[/bold]\n" + "\n".join(lines)
            )
        except Exception:  # noqa: BLE001
            return

    def _show_home(self) -> None:
        first_run = self._last_session is None and not list_profiles()
        actions = home_actions(first_run=first_run)
        lines = [f"{item['goal']}: {item['command']}" for item in actions[:6]]
        self.query_one("#first-launch-panel", Static).update(
            "[bold]What should I do?[/bold]\n" + "\n".join(lines)
        )
        self.notify("Goal-based starting points are shown above.", severity="information")

    def _show_setup_wizard(self) -> None:
        self._set_wizard_step(0)
        self.query_one("#domain", Input).focus()
        self._refresh_first_launch_panel()
        self.notify(
            "Setup starts with workspace, target, access, profile, then quickstart.",
            severity="information",
        )

    def _show_recommendations(self) -> None:
        cap = self._selected()
        if cap:
            suggestions = suggested_next_actions(cap)[:3]
            text = "Recommended next actions: " + (
                ", ".join(suggestions)
                if suggestions
                else "run the selected capability and inspect findings"
            )
        else:
            text = "Recommended starting point: ldap-enum for safe directory reconnaissance."
        self.query_one("#recommendations-panel", Static).update(text)

    def _apply_template(self, template: str) -> None:
        choices = {
            "recon": ("ldap-enum", "Safe reconnaissance"),
            "adcs": ("adcs-enum", "AD CS review"),
            "full": ("ldap-enum", "Full assessment"),
        }
        capability_id, label = choices[template]
        if not capability_registry.get(capability_id):
            self.notify(f"Template unavailable: {capability_id}", severity="warning")
            return
        self.selected_cap = capability_id
        self._update_help()
        self._show_recommendations()
        self._set_wizard_step(0)
        self.notify(
            f"{label} template selected. Enter the authorized target to continue.",
            severity="information",
        )

    def _toggle_pause(self) -> None:
        if not self._capability_running:
            return
        if self._pause_requested.is_set():
            self._pause_requested.clear()
            self.query_one("#pause-btn", Button).label = "Pause"
            self._show_log("[green]Execution resumed at the next safe boundary.[/]")
        else:
            self._pause_requested.set()
            self.query_one("#pause-btn", Button).label = "Resume"
            self._show_log(
                "[yellow]Pause requested; execution will pause at the next safe boundary.[/]"
            )

    def _show_run_summary(self) -> None:
        cap = self._selected()
        if not cap:
            return
        target = self.query_one("#domain", Input).value.strip() or "(missing)"
        dc = self.query_one("#dc_ip", Input).value.strip() or "(missing)"
        risk = "destructive" if cap.destructive else "read-only"
        estimate = "1–3 minutes" if cap.category in {"discovery", "analysis"} else "3–10 minutes"
        self.query_one("#summary-panel", Static).update(
            f"[bold]Run summary[/bold] · {cap.id} · {risk}\n"
            f"Target: {target} @ {dc}\nEstimated duration: {estimate} · OPSEC: {active_opsec().upper()}"
        )

    def _refresh_workflow_panel(self) -> None:
        if not self._workflow:
            return
        state = self._workflow.state
        recommendations = self._workflow.recommendations(limit=3)
        next_action = recommendations[0].title if recommendations else "No pending actions"
        self.query_one("#workflow-state-panel", Static).update(
            f"Workflow: {state.phase} · {state.status} · {state.progress:.0f}% · "
            f"risk {state.risk_score:.0f}\n"
            f"Findings: {len(state.findings)} total / {len(state.open_findings)} open · Next: {next_action}"
        )

    def _ensure_workflow_started(self) -> None:
        if not self._workflow:
            self._workflow = WorkflowEngine(default_workspace_dir())
        if not self._workflow.state.audit_log:
            self._workflow.start(actor="tui")
        if "scope-authorized" not in self._workflow.state.completed_steps:
            self._workflow.complete_action("authorize-scope", actor="tui-review")
        self._refresh_workflow_panel()

    def _ingest_session_findings(self, session: Path) -> None:
        if not self._workflow:
            return
        try:
            payload = json.loads((session / "findings.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        documents = payload.get("findings", []) if isinstance(payload, dict) else payload
        if not isinstance(documents, list):
            return
        for document in documents:
            if isinstance(document, dict) and document.get("id") and document.get("title"):
                self._workflow.ingest_finding(finding_from_document(document), actor="session")
        try:
            self._workflow.complete_step("discovery-complete", actor="tui", phase="validation")
            self._refresh_workflow_panel()
        except OSError as exc:
            # Findings remain available in the session even when the optional
            # workflow checkpoint cannot be persisted (e.g. read-only home).
            self._show_log(f"[yellow]Workflow checkpoint unavailable:[/] {exc}")

    def _wizard_next(self) -> None:
        if self._wizard_step == 0:
            if self._validate_target() is None:
                return
            self._set_wizard_step(1)
            self.query_one("#username", Input).focus()
        elif self._wizard_step == 1:
            self._set_wizard_step(2)
            self.query_one("#search", Input).focus()
        elif self._wizard_step == 2:
            if not self._selected():
                self.notify("Choose a capability before continuing.", severity="warning")
                self.query_one("#search", Input).focus()
                return
            self._set_wizard_step(3)
            self._review_run()
            self._show_run_summary()
            self._show_recommendations()
        elif self._wizard_step == 3:
            self._review_run()
            cap = self._selected()
            if cap and (not cap.destructive or self._reviewed_cap == cap.id):
                self._set_wizard_step(4)
                self._show_run_summary()
            else:
                self.notify("Complete the review checklist before continuing.", severity="warning")
        elif self._wizard_step == 4:
            self._start_run()
        else:
            self._reset_form()
            self.selected_cap = None
            self._set_wizard_step(0)
            self.query_one("#domain", Input).focus()

    def _wizard_back(self) -> None:
        if self._wizard_step > 0 and not self._capability_running:
            self._set_wizard_step(self._wizard_step - 1)

    def _wizard_start_over(self) -> None:
        if self._capability_running:
            return
        self._reset_form()
        self.selected_cap = None
        self._set_wizard_step(0)
        self.query_one("#domain", Input).focus()
        self.notify(
            "Guided workflow reset. Start with the authorized target.", severity="information"
        )

    def _form_values(self) -> dict[str, Any]:
        values: dict[str, Any] = {}
        for widget_id in (
            "domain",
            "dc_ip",
            "username",
            "password",
            "hashes",
            "aes_key",
            "ccache",
            "creds_file",
            "scope",
            "start",
        ):
            values[widget_id] = self.query_one(f"#{widget_id}", Input).value
        for widget_id in ("kerberos", "ldaps", "include_secrets", "force"):
            values[widget_id] = self.query_one(f"#{widget_id}", Switch).value
        return values

    def _reset_form(self) -> None:
        """Clear local form values with a one-step undo; no target action is involved."""
        self._form_snapshot = self._form_values()
        for widget_id in (
            "domain",
            "dc_ip",
            "username",
            "password",
            "hashes",
            "aes_key",
            "ccache",
            "creds_file",
            "start",
        ):
            self.query_one(f"#{widget_id}", Input).value = ""
        self.query_one("#scope", Input).value = "high-value"
        for widget_id in ("kerberos", "ldaps", "include_secrets", "force"):
            self.query_one(f"#{widget_id}", Switch).value = False
        self.query_one("#undo-reset-btn", Button).disabled = False
        self._reviewed_cap = None
        self._update_status()
        self._update_run_gate()
        self._update_engagement_dashboard()
        self.notify("Form reset. Undo is available until the next reset.", severity="information")

    def action_undo_form_reset(self) -> None:
        self._undo_form_reset()

    def _undo_form_reset(self) -> None:
        if self._form_snapshot is None:
            self.notify("Nothing to undo.", severity="information")
            return
        for widget_id in (
            "domain",
            "dc_ip",
            "username",
            "password",
            "hashes",
            "aes_key",
            "ccache",
            "creds_file",
            "scope",
            "start",
        ):
            self.query_one(f"#{widget_id}", Input).value = str(self._form_snapshot[widget_id])
        for widget_id in ("kerberos", "ldaps", "include_secrets", "force"):
            self.query_one(f"#{widget_id}", Switch).value = bool(self._form_snapshot[widget_id])
        self._form_snapshot = None
        self.query_one("#undo-reset-btn", Button).disabled = True
        self._update_status()
        self._update_run_gate()
        self._update_engagement_dashboard()
        self.notify("Form restored.", severity="information")

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
        glossary = glossary_definition(cap.id)
        glossary_line = f"\nGlossary: {glossary}" if glossary else ""
        recent = ", ".join(recent_capabilities()) or "none yet"
        pinned = ", ".join(favorite_capabilities()) or "none"
        difficulty = capability_difficulty(cap)
        self.query_one("#help-panel", Static).update(
            f"[bold]{cap.id}[/]\n{cap.summary}\nCategory: {cap.category}\n"
            f"Difficulty: {difficulty['level']} — {difficulty['reason']}\n"
            f"Safety: {safety_summary(cap)['level']} — {plain_description(cap)}\n"
            f"Required: {required}\nOptional: {optional}{notes}{glossary_line}\n"
            f"Recent: {recent}\nPinned: {pinned}"
        )

    def _refresh_pin_button(self) -> None:
        button = self.query_one("#pin-selected-btn", Button)
        button.disabled = self.selected_cap is None
        button.label = (
            "Unpin selected"
            if self.selected_cap and self.selected_cap in favorite_capabilities()
            else "Pin selected"
        )

    def _toggle_selected_favorite(self) -> None:
        if not self.selected_cap:
            self.notify("Select a capability first.", severity="warning")
            return
        try:
            pinned = self.selected_cap not in favorite_capabilities()
            set_favorite_capability(self.selected_cap, favorite=pinned)
        except OSError as exc:
            self.notify(f"Could not save pinned capabilities: {exc}", severity="error")
            return
        self._refresh_pin_button()
        self._update_help()
        self.notify(f"{'Pinned' if pinned else 'Unpinned'} {self.selected_cap}.")

    def _restore_latest_target(self) -> None:
        targets = recent_targets(limit=1)
        if not targets:
            self.notify("No saved non-secret targets yet.", severity="information")
            return
        target = targets[0]
        self.query_one("#domain", Input).value = target["domain"]
        self.query_one("#dc_ip", Input).value = target["dc_ip"]
        self.query_one("#scope", Input).value = target["scope"]
        self._update_status()
        self._update_readiness()
        self._validate_target_inline()
        self._update_engagement_dashboard()
        self.notify("Restored the most recent target. Credentials were not stored.")

    def action_show_cheat_sheet(self) -> None:
        self.notify(
            "Keys: r run · v review · d dry run · l refresh · s sessions · e last error\n"
            "p show/hide password · u undo reset · Ctrl-K search · q quit",
            title="Keybinding cheat sheet",
            severity="information",
            timeout=8,
        )

    def _update_status(self) -> None:
        domain = self.query_one("#domain", Input).value or "(none)"
        dc = self.query_one("#dc_ip", Input).value or ""
        target = f"{domain}" + (f" @ {dc}" if dc else "")
        cap = self.selected_cap or "(none)"
        state = "RUNNING" if self._capability_running else "idle"
        workspace = default_workspace_dir()
        disk_path = workspace
        while not disk_path.exists() and disk_path != disk_path.parent:
            disk_path = disk_path.parent
        free = shutil.disk_usage(disk_path).free // (1024**3)
        vault = "vault key present" if os.environ.get("ADAF_SESSION_VAULT_KEY") else "no vault key"
        opsec = active_opsec()
        self.query_one("#status", Static).update(
            f"Target: {target}  |  Cap: {cap}  |  {state}  |  OPSEC: {opsec.upper()}  |  "
            f"{str(workspace)[-32:]} ({free} GB free, {vault})"
        )

    def _update_engagement_dashboard(self) -> None:
        """Render a compact, non-secret view of the active engagement state."""
        domain = self.query_one("#domain", Input).value.strip()
        dc_ip = self.query_one("#dc_ip", Input).value.strip()
        target = f"{domain} @ {dc_ip}" if domain and dc_ip else "Target details required"
        scope = self.query_one("#scope", Input).value.strip() or "high-value"
        cap = self._selected()
        if not cap:
            authorization = "No capability selected"
        elif cap.destructive and self._reviewed_cap != cap.id:
            authorization = "Review acknowledgement required"
        elif cap.destructive:
            authorization = "Reviewed for selected capability"
        else:
            authorization = "Read-only capability selected"
        if self._capability_running:
            health = f"Running · {self._active_stage or 'preparing'}"
        elif self._last_session and self._last_session.is_dir():
            health = f"Last session ready · {self._last_session.name}"
        elif domain and dc_ip:
            health = "Ready to review"
        else:
            health = "Awaiting target details"
        try:
            self.query_one("#engagement-dashboard", Static).update(
                "[bold]Engagement dashboard[/bold]\n"
                f"Target: {target} · Scope: {scope} · OPSEC: {active_opsec().upper()}\n"
                f"Authorization: {authorization} · Session health: {health}"
            )
        except Exception:  # noqa: BLE001
            # Test/minimal screens and transitional layouts may not mount the
            # optional dashboard widget; background capability completion must
            # not fail solely because that presentation surface is absent.
            return

    def _update_credential_strip(self) -> None:
        labels = []
        for widget_id, label in (
            ("password", "password"),
            ("hashes", "NT hash"),
            ("aes_key", "AES key"),
            ("ccache", "ccache"),
        ):
            if self.query_one(f"#{widget_id}", Input).value.strip():
                labels.append(label)
        self.query_one("#credential-strip", Static).update(
            "Credential material: "
            + (", ".join(labels) if labels else "none")
            + "  [dim](values hidden)[/]"
        )

    def _refresh_profile_hint(self) -> None:
        names = ", ".join(profile["name"] for profile in list_profiles()) or "none saved"
        self.query_one("#profile-name", Input).placeholder = f"Profile name ({names})"

    def _apply_profile(self) -> None:
        name = self.query_one("#profile-name", Input).value.strip()
        profile = get_profile(name)
        if not profile:
            self.notify("Profile not found.", severity="warning")
            return
        for key, widget_id in (
            ("domain", "domain"),
            ("dc_ip", "dc_ip"),
            ("username", "username"),
            ("scope", "scope"),
        ):
            if profile.get(key) is not None:
                self.query_one(f"#{widget_id}", Input).value = str(profile[key])
        for key, widget_id in (("kerberos", "kerberos"), ("ldaps", "ldaps")):
            if profile.get(key) is not None:
                self.query_one(f"#{widget_id}", Switch).value = bool(profile[key])
        self._update_status()
        self._update_engagement_dashboard()
        self.notify(f"Loaded profile: {name}")

    def _save_profile(self, *, make_default: bool = False) -> None:
        name = self.query_one("#profile-name", Input).value.strip()
        if not name:
            self.notify("Enter a profile name first.", severity="warning")
            return
        values = {
            "domain": self.query_one("#domain", Input).value.strip(),
            "dc_ip": self.query_one("#dc_ip", Input).value.strip(),
            "username": self.query_one("#username", Input).value.strip(),
            "scope": self.query_one("#scope", Input).value.strip(),
            "kerberos": self.query_one("#kerberos", Switch).value,
            "ldaps": self.query_one("#ldaps", Switch).value,
            "opsec_profile": active_opsec(),
        }
        try:
            set_profile(name, values)
            if make_default:
                config = load_user_config()
                config["profile.default"] = name
                save_user_config(config)
            self._refresh_profile_hint()
            self.notify(f"Saved profile: {name}" + (" (default)" if make_default else ""))
        except ValueError as exc:
            self.notify(str(exc), severity="error")

    def _update_run_gate(self) -> None:
        cap = self._selected()
        enabled = not self._capability_running
        if cap and cap.destructive:
            required = risk_checklist(cap)["items"]
            complete = all(
                not item["required"] or self.query_one(f"#check-{item['id']}", Checkbox).value
                for item in required
            )
            enabled = (
                enabled
                and self.query_one("#force", Switch).value
                and complete
                and self._reviewed_cap == cap.id
            )
        self.query_one("#run-btn", Button).disabled = not enabled

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

    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()

    def _set_advanced_credentials_visible(self, visible: bool) -> None:
        self._advanced_credentials_visible = visible
        for widget_id in ("hashes", "aes_key", "ccache", "creds_file"):
            self.query_one(f"#{widget_id}", Input).display = visible
        self.query_one("#advanced-creds-btn", Button).label = (
            "Hide advanced credentials" if visible else "Advanced credentials"
        )

    def _show_command_only(self) -> None:
        cap = self._selected()
        level = safety_summary(cap)["level"] if cap else "SELECT A CAPABILITY"
        self.query_one("#review-panel", Static).update(
            f"[bold]Command only[/bold]\nSafety: {level}\n{self._ready_command()}"
        )

    def _explain_findings(self) -> None:
        if not self._last_session:
            self.notify("Load a session first.", severity="information")
            return
        findings = self._read_json(self._last_session / "findings.json").get("findings") or []
        explanations = [explain_finding(item) for item in findings if isinstance(item, dict)]
        self.query_one("#session-panel", Static).update(
            "[bold]Finding explanations[/bold]\n"
            + ("\n".join(explanations) or "No findings to explain.")
        )

    def action_jump_to_error(self) -> None:
        for line in reversed(self._log_lines):
            if "error" in line.lower():
                self.query_one("#log-filter", Input).value = "error"
                self.notify("Showing the most recent error.", severity="information")
                return
        self.notify("No error is recorded in this TUI session.", severity="information")

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
        self._reviewed_cap = None
        spec = capability_option_spec(cap.id, cap.destructive)
        force = self.query_one("#force", Switch).value
        risk = (
            "DESTRUCTIVE — Force is enabled."
            if cap.destructive and force
            else "DESTRUCTIVE — Force is required."
            if cap.destructive
            else "Read-only / non-destructive"
        )
        checklist = risk_checklist(cap)
        for item in checklist["items"]:
            checkbox = self.query_one(f"#check-{item['id']}", Checkbox)
            checkbox.label = item["label"] + (" *" if item["required"] else "")
            checkbox.value = item["id"] == "force" and force
        command = self._ready_command(cap.id)
        self.query_one("#review-panel", Static).update(
            f"[bold]Execution review[/bold]  {cap.id}\n"
            f"Target: {target[0]} @ {target[1]}\nCategory: {cap.category}  |  Risk: {risk}\n"
            f"Required contract: {', '.join(spec.required) or 'session/workspace input'}\n"
            f"Opsec: {active_opsec().upper()} — {checklist['opsec_hint']}\n"
            f"Ready command: [dim]{command}[/]\n"
            "Check required items, then acknowledge the review."
        )
        self._update_run_gate()
        if cap.destructive and not force:
            self.notify(
                "Review shows a destructive capability; enable Force only when authorized.",
                severity="warning",
            )

    def _acknowledge_review(self) -> None:
        cap = self._selected()
        if not cap:
            self.notify("Select a capability first.", severity="warning")
            return
        required = risk_checklist(cap)["items"]
        incomplete = [
            item["label"]
            for item in required
            if item["required"] and not self.query_one(f"#check-{item['id']}", Checkbox).value
        ]
        if incomplete:
            self.notify(
                "Complete required checklist items before acknowledging.", severity="warning"
            )
            return
        self._reviewed_cap = cap.id
        self._update_run_gate()
        self._update_readiness()
        self._update_engagement_dashboard()
        self.notify("Review acknowledged. Run is enabled when permitted.")

    def _ready_command(self, capability_id: str | None = None) -> str:
        return build_ready_command(
            capability_id or self.selected_cap or "<capability>",
            domain=self.query_one("#domain", Input).value.strip() or None,
            dc_ip=self.query_one("#dc_ip", Input).value.strip() or None,
            username=self.query_one("#username", Input).value.strip() or None,
            force=self.query_one("#force", Switch).value,
            extra={"scope": self.query_one("#scope", Input).value.strip() or "high-value"},
        )

    def _copy_ready_command(self) -> None:
        if not self.selected_cap:
            self.notify("Select a capability first.", severity="warning")
            return
        try:
            self.copy_to_clipboard(self._ready_command())
            self.notify("Ready command copied to clipboard.")
        except Exception:  # noqa: BLE001
            self.notify("Clipboard is unavailable in this terminal.", severity="warning")

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
        cap = self._selected()
        if cap and cap.destructive and self._reviewed_cap != cap.id:
            self.notify(
                "Review and acknowledge required checklist items before running.",
                severity="warning",
            )
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
        record_recent_target(domain, dc_ip, scope)
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
        try:
            self._ensure_workflow_started()
        except Exception as exc:  # noqa: BLE001
            self._show_log(f"[yellow]Workflow state unavailable:[/] {exc}")
        self._show_log(f"\n[bold]→ {capability_id}[/] on {domain} @ {dc_ip}")
        self._cancel_requested.clear()
        self._pause_requested.clear()
        self._capability_running = True
        self._active_stage = "prepare"
        self.query_one("#cancel-btn", Button).disabled = False
        self.query_one("#pause-btn", Button).disabled = False
        self.query_one("#reports-btn", Button).disabled = True
        self.query_one("#package-btn", Button).disabled = True
        self._update_status()
        self._update_progress()
        self._update_engagement_dashboard()

        def worker() -> None:
            def log_fn(msg: str) -> None:
                while self._pause_requested.is_set() and not self._cancel_requested.is_set():
                    threading.Event().wait(0.1)
                lowered = msg.lower()
                if "connect" in lowered or "ldap bind" in lowered:
                    self._active_stage = "connect"
                elif "resolved" in lowered or "session directory" in lowered:
                    self._active_stage = "analyze"
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
                self.call_from_thread(self._update_engagement_dashboard)
                summary = out.get("graph_summary") or {}
                self._write_run_log(
                    f"[green]Done[/] session={out['session_id']}  nodes={summary.get('nodes', 0)} edges={summary.get('edges', 0)}"
                )
                self.call_from_thread(self._load_findings, Path(out["session_path"]))
                self.call_from_thread(self._ingest_session_findings, Path(out["session_path"]))
                self.call_from_thread(self._show_next_actions, capability_id)
                self.call_from_thread(self._set_wizard_step, 5)
                self.call_from_thread(
                    self.query_one("#reports-btn", Button).__setattr__, "disabled", False
                )
                self.call_from_thread(
                    self.query_one("#package-btn", Button).__setattr__, "disabled", False
                )
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
                self._active_stage = "next-actions"
                self.call_from_thread(
                    self.query_one("#cancel-btn", Button).__setattr__, "disabled", True
                )
                self.call_from_thread(
                    self.query_one("#pause-btn", Button).__setattr__, "disabled", True
                )
                self.call_from_thread(
                    self.query_one("#pause-btn", Button).__setattr__, "label", "Pause"
                )
                self.call_from_thread(self._update_status)
                self.call_from_thread(self._update_progress)
                self.call_from_thread(self._update_run_gate)
                self.call_from_thread(self._update_engagement_dashboard)
                self.call_from_thread(self._refresh_first_launch_panel)

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
                findings = self._read_json(session / "findings.json").get("findings") or []
                severity: dict[str, int] = {}
                for finding in findings if isinstance(findings, list) else []:
                    if isinstance(finding, dict):
                        key = str(finding.get("severity", "unknown")).lower()
                        severity[key] = severity.get(key, 0) + 1
                heat = " ".join(
                    f"{label[0].upper()}:{severity.get(label, 0)}"
                    for label in ("critical", "high", "medium", "low")
                )
                rows.append(
                    f"{meta.get('session_id', session.name)}  {meta.get('created_at', '')[:19]}  "
                    f"findings:{sum(severity.values())} [{heat}]"
                )
        self.query_one("#session-panel", Static).update(
            "[bold]Recent sessions[/bold]\n" + ("\n".join(rows[:8]) or "No sessions found.")
        )

    def _create_reports(self) -> None:
        if not self._last_session or not self._last_session.is_dir():
            self.notify("Complete a session before creating reports.", severity="warning")
            return
        try:
            result = generate_report_bundle(self._last_session)
            self.query_one("#session-panel", Static).update(
                "[bold]Reports created[/bold]\n"
                + "\n".join(
                    f"{key}: {value}"
                    for key, value in result.items()
                    if key.endswith("html") or key.endswith("pdf")
                )
            )
            self.notify(
                "Executive, technical, and remediation reports are ready.", severity="information"
            )
        except (OSError, ValueError, RuntimeError) as exc:
            self._show_log(f"[red]Report generation failed:[/] {exc}")
            self.notify("Report generation failed. See the log for remediation.", severity="error")

    def _package_evidence(self) -> None:
        if not self._last_session or not self._last_session.is_dir():
            self.notify("Complete a session before packaging evidence.", severity="warning")
            return
        destination = self._last_session.parent / f"{self._last_session.name}-evidence.zip"
        try:
            result = package_evidence(self._last_session, destination)
            self.query_one("#session-panel", Static).update(
                f"[bold]Evidence package ready[/bold]\nArchive: {result['archive']}\n"
                f"Files: {result['file_count']} · Profile: {result['profile']}"
            )
            self.notify("Redacted evidence package created.", severity="information")
        except (OSError, ValueError, RuntimeError) as exc:
            self._show_log(f"[red]Evidence packaging failed:[/] {exc}")
            self.notify("Evidence packaging failed. See the log for remediation.", severity="error")

    def _show_next_actions(self, capability_id: str) -> None:
        cap = capability_registry.get(capability_id)
        if not cap:
            return
        if self._safe_mode:
            suggestions = beginner_next_actions(cap)
        else:
            suggestions = []
            for item in suggested_next_actions(cap):
                follow_on = capability_registry.get(item)
                if follow_on:
                    suggestions.append({"id": item, "message": follow_on.summary})
        if suggestions:
            suggestion_lines = [f"• {item['id']} — {item['message']}" for item in suggestions]
            self.query_one("#review-panel", Static).update(
                "[bold]Suggested next[/bold]\n"
                + "\n".join(suggestion_lines)
                + "\nSelect a suggested capability in the sidebar, then review it."
            )

    def _update_progress(self) -> None:
        cap = self._selected()
        if not cap:
            return
        stages = [item["id"] for item in format_stages_progress(cap)["stages"]]
        current = self._active_stage
        rendered = " → ".join(f"[bold cyan]{s}[/]" if s == current else s for s in stages)
        self.query_one("#progress", Static).update(f"Stages: {rendered}")

    def _show_findings(self) -> None:
        if self._last_session:
            self._load_findings(self._last_session)
        else:
            self.query_one("#session-panel", Static).update(
                "[bold]Findings dashboard[/bold]\nRun a capability or select a session first."
            )

    def _show_cockpit(self) -> None:
        if not self._last_session:
            self.notify("Complete or select a session first.", severity="information")
            return
        payload = evidence_cockpit(self._last_session)
        focus = payload.get("priority_focus") or []
        self.query_one("#session-panel", Static).update(
            "[bold]Evidence cockpit[/bold]\n"
            f"Findings: {payload['dashboard'].get('finding_count', 0)}\n"
            f"Priority: " + (", ".join(str(item.get("title")) for item in focus) or "none")
        )

    def _show_attack_paths(self) -> None:
        """Show ranked saved paths and their observed edge details offline."""
        panel = self.query_one("#attack-path-panel", Static)
        if not self._last_session:
            self._clear_attack_edges()
            panel.update(
                "[bold]Attack-path workspace[/bold]\n"
                "Complete or select a session with saved graph evidence first."
            )
            return
        graph_path = self._last_session / "graph.json"
        if not graph_path.is_file():
            self._clear_attack_edges()
            panel.update(
                f"[bold]Attack-path workspace[/bold]  {self._last_session.name}\n"
                "No graph.json evidence is available for this session."
            )
            return
        try:
            payload = graph_explorer(graph_path, limit=5)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self._clear_attack_edges()
            panel.update(
                "[bold]Attack-path workspace[/bold]\n"
                f"Saved graph could not be read: {exc}"
            )
            return
        summary = payload.get("summary") or {}
        paths = payload.get("paths") or []
        lines = [
            f"[bold]Attack-path workspace[/bold]  {self._last_session.name}",
            f"Nodes: {summary.get('nodes', 0)} · Edges: {summary.get('edges', 0)} · "
            f"Ranked paths: {len(paths)} · Offline inspection only",
        ]
        if not paths:
            lines.append("No ranked paths were found in the saved graph.")
        edges: list[dict[str, Any]] = []
        seen_edges: set[tuple[str, str, str]] = set()
        for number, path in enumerate(paths, start=1):
            if not isinstance(path, dict):
                continue
            nodes = path.get("path") or []
            relations = path.get("edges") or []
            for index, relation in enumerate(relations):
                if index + 1 >= len(nodes):
                    continue
                key = (str(nodes[index]), str(nodes[index + 1]), str(relation))
                if key in seen_edges:
                    continue
                seen_edges.add(key)
                try:
                    details = inspect_edge(
                        graph_path,
                        source=key[0],
                        target=key[1],
                        relation=key[2],
                    ).get("edges", [])
                except (OSError, ValueError, KeyError, TypeError):
                    details = []
                if details and isinstance(details[0], dict):
                    edges.append(details[0])
            route = " → ".join(str(node).split("@", 1)[0] for node in nodes)
            terminal_relation = relations[-1] if relations else "-"
            lines.append(
                f"{number}. {route or 'unresolved'}  "
                f"score={path.get('score', 0)}  terminal={terminal_relation}"
            )
            if relations:
                lines.append(
                    "   Edge detail: "
                    + " | ".join(
                        f"{str(nodes[index]).split('@', 1)[0]}"
                        f" --{relation}--> {str(nodes[index + 1]).split('@', 1)[0]}"
                        for index, relation in enumerate(relations)
                        if index + 1 < len(nodes)
                    )
                    + f"  ({path.get('length', len(relations))} observed relation(s))"
                )
        panel.update("\n".join(lines))
        edge_list = self.query_one("#attack-edge-list", ListView)
        self._selected_attack_edge = None
        edge_list.clear()
        for edge in edges:
            edge_list.append(AttackEdgeItem(edge))
        self.query_one("#attack-edge-detail", Static).update(
            f"{len(edges)} observed edge(s) available for review. Select one for details."
            if edges
            else "No selectable observed edges were found in the ranked paths."
        )
        self.query_one("#prepare-edge-btn", Button).disabled = True

    def _clear_attack_edges(self) -> None:
        """Clear edge selection when the active session has no graph workspace."""
        self._selected_attack_edge = None
        self.query_one("#attack-edge-list", ListView).clear()
        self.query_one("#attack-edge-detail", Static).update(
            "Select an observed edge to inspect evidence, risk, ATT&CK mapping, and remediation."
        )
        self.query_one("#prepare-edge-btn", Button).disabled = True

    def _show_attack_edge(self, edge: dict[str, Any]) -> None:
        """Render the selected edge's evidence and safety context without executing it."""
        self._selected_attack_edge = edge
        evidence = edge.get("evidence") or {}
        prerequisites = edge.get("prerequisites") or []
        mapping = edge.get("attack_mapping") or []
        telemetry = edge.get("expected_telemetry") or []
        detail = (
            f"[bold]Selected edge[/bold]\n"
            f"{edge.get('source', '?')} --{edge.get('relation', 'unknown')}--> "
            f"{edge.get('target', '?')}\n"
            f"Exploitability: {edge.get('exploitability', 'unknown')} · Risk: {edge.get('risk', 'unknown')}\n"
            f"Prerequisites: {', '.join(str(value) for value in prerequisites) or 'not specified'}\n"
            f"Evidence: {evidence or 'none recorded'}\n"
            f"ATT&CK: {', '.join(str(value) for value in mapping) or 'not mapped'}\n"
            f"Telemetry: {', '.join(str(value) for value in telemetry) or 'not specified'}\n"
            f"Remediation: {edge.get('remediation', 'not specified')}"
        )
        self.query_one("#attack-edge-detail", Static).update(detail)
        self.query_one("#prepare-edge-btn", Button).disabled = False

    def _prepare_edge_validation(self) -> None:
        """Prepare a capability review from the selected edge; never execute it."""
        edge = self._selected_attack_edge
        if not edge:
            self.notify("Select an observed edge first.", severity="information")
            return
        relation = str(edge.get("relation", ""))
        capability_by_relation = {
            "DCSync": "dcsync",
            "ESC1": "cert-request",
            "ESC8WebEnrollment": "cert-request",
            "WriteGPO": "gpo-abuse",
            "WriteSYSVOL": "gpo-abuse",
            "AllowedToAct": "s4u-abuse",
            "WriteRBCD": "s4u-abuse",
            "SpoolerOpen": "coercion-map",
            "EfsrpcOpen": "coercion-map",
        }
        capability_id = capability_by_relation.get(relation, "attack-paths")
        capability = capability_registry.get(capability_id)
        if not capability:
            self.notify(
                f"No validation capability is registered for {relation or 'this edge'}.",
                severity="warning",
            )
            return
        self.selected_cap = capability.id
        self._reviewed_cap = None
        self._update_help()
        self._update_status()
        self._update_readiness()
        self._update_run_gate()
        self.query_one("#review-panel", Static).update(
            f"[bold]Edge validation handoff — review required[/bold]\n"
            f"Edge: {edge.get('source', '?')} --{relation or 'unknown'}--> {edge.get('target', '?')}\n"
            f"Suggested capability: {capability.id} — {capability.summary}\n"
            f"Risk: {'destructive; Force and acknowledgement required' if capability.destructive else 'read-only'}\n"
            f"Ready command: [dim]{self._ready_command(capability.id)}[/]\n"
            "Select Review to inspect prerequisites and success criteria before any execution."
        )
        self.notify(f"Prepared {capability.id} for review; nothing has executed.", severity="information")

    def _show_timeline(self) -> None:
        if not self._last_session:
            self.notify("Complete or select a session first.", severity="information")
            return
        payload = session_timeline(self._last_session, limit=12)
        self.query_one("#session-panel", Static).update(
            "[bold]Engagement timeline[/bold]\n"
            + "\n".join(
                f"{item.get('time') or '-'}  {item['type']}  {item.get('capability') or ''}"
                for item in payload["events"][-8:]
            )
        )

    def _show_copilot(self) -> None:
        if not self._last_session:
            self.notify("Complete or select a session first.", severity="information")
            return
        payload = copilot_recommendations(self._last_session)
        self.query_one("#review-panel", Static).update(
            "[bold]Evidence copilot — suggestions only[/bold]\n"
            + "\n".join(
                f"• {item['action']} — {item['why']}\n  {item['command']}"
                for item in payload["recommendations"]
            )
        )

    def _explain_selected(self) -> None:
        """Show the selected capability in novice-friendly language."""
        if not self.selected_cap:
            self.notify("Select a capability first.", severity="information")
            return
        self._update_help()
        self.query_one("#review-panel", Static).update(
            "[bold]Plain-language explanation[/bold]\n"
            + str(self.query_one("#help-panel", Static).render())
            + "\n\nUse Review to see the exact command, risk, and pre-flight checklist."
        )

    def _show_what_next(self) -> None:
        """Show the next safe action for the current selection or session."""
        if self.selected_cap:
            self._show_next_actions(self.selected_cap)
        else:
            self._show_home()

    def _copy_findings(self) -> None:
        text = str(self.query_one("#session-panel", Static).render())
        try:
            self.copy_to_clipboard(text)
            self.notify("Findings dashboard copied to clipboard.", severity="information")
        except Exception:  # noqa: BLE001
            self.notify("Clipboard is unavailable in this terminal.", severity="warning")

    def _load_findings(self, session: Path) -> None:
        dashboard = session_findings_dashboard(session)
        top_paths = dashboard.get("top_paths") or []
        severity_counts = dashboard.get("severity_counts") or {}
        triage_counts = dashboard.get("triage_counts") or {}
        summary = dashboard.get("graph") or {}
        path_lines = [
            "  " + " → ".join(str(x).split("@")[0] for x in path.get("path", [])[:5])
            for path in top_paths[:3]
            if isinstance(path, dict)
        ]
        self.query_one("#session-panel", Static).update(
            f"[bold]Findings dashboard[/bold]  {session.name}\n"
            f"Nodes: {summary.get('nodes', 0)}  Edges: {summary.get('edges', 0)}  "
            f"Findings: {dashboard.get('finding_count', 0)}  Severity: {severity_counts or 'none'}\n"
            f"Triage: {triage_counts or {'open': 0}}\n"
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
            "home-btn": self._show_home,
            "explain-selected-btn": self._explain_selected,
            "what-next-btn": self._show_what_next,
            "setup-btn": self._show_setup_wizard,
            "reset-form-btn": self._reset_form,
            "undo-reset-btn": self._undo_form_reset,
            "sessions-btn": self._show_sessions,
            "findings-btn": self._show_findings,
            "cockpit-btn": self._show_cockpit,
            "attack-paths-btn": self._show_attack_paths,
            "prepare-edge-btn": self._prepare_edge_validation,
            "timeline-btn": self._show_timeline,
            "copilot-btn": self._show_copilot,
            "command-only-btn": self._show_command_only,
            "advanced-creds-btn": lambda: self._set_advanced_credentials_visible(
                not self._advanced_credentials_visible
            ),
            "copy-btn": self._copy_findings,
            "copy-command-btn": self._copy_ready_command,
            "pin-selected-btn": self._toggle_selected_favorite,
            "use-latest-target-btn": self._restore_latest_target,
            "ack-review-btn": self._acknowledge_review,
            "load-profile-btn": self._apply_profile,
            "save-profile-btn": self._save_profile,
            "default-profile-btn": lambda: self._save_profile(make_default=True),
            "toggle-password-btn": self._toggle_password,
            "pause-btn": self._toggle_pause,
            "reports-btn": self._create_reports,
            "package-btn": self._package_evidence,
            "template-recon": lambda: self._apply_template("recon"),
            "template-adcs": lambda: self._apply_template("adcs"),
            "template-full": lambda: self._apply_template("full"),
            "template-help": lambda: self._apply_template("recon"),
            "resume-btn": self._resume_wizard,
            "wizard-next": self._wizard_next,
            "wizard-back": self._wizard_back,
            "wizard-start-over": self._wizard_start_over,
        }
        action = actions.get(event.button.id or "")
        if action:
            action()


def run_tui() -> None:
    ADAFAttackApp().run()
