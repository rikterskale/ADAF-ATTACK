"""Textual interaction tests for the ADAF-ATTACK TUI."""

from __future__ import annotations

import asyncio
import json
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from textual.widgets import Input, ListView, Static

from adaf_attack.core import user_config
from adaf_attack.core.workflow_engine import WorkflowEngine
from adaf_attack.tui import app as tui_app
from adaf_attack.tui.app import ADAFAttackApp


async def _wait_for(pilot, predicate, *, timeout: float = 5.0) -> None:
    """Pump the Textual event loop until ``predicate()`` holds, or fail.

    ``_start_run`` executes the capability on a daemon thread whose completion
    (and its ``_capability_running = False`` reset) is reached only after its
    ``call_from_thread`` log callbacks are marshalled back onto the app loop. A
    fixed ``asyncio.sleep`` can't reliably pump the loop enough times on a loaded
    CI runner, so we poll. A genuine regression still fails: the timeout raises.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.02)
        await pilot.pause()
    if not predicate():
        raise AssertionError("condition was not met within the timeout")


def test_tui_starts_populates_capabilities_and_updates_status() -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            capabilities = app.query_one("#cap-list", ListView)
            assert len(capabilities) > 10
            assert "Workflow:" in str(app.query_one("#workflow-state-panel", Static).render())
            app.query_one("#domain", Input).value = "corp.test"
            app.query_one("#dc_ip", Input).value = "192.0.2.10"
            app.selected_cap = "ldap-enum"
            app._update_status()
            assert "corp.test @ 192.0.2.10" in str(app.query_one("#status", Static).render())
            assert "ldap-enum" in str(app.query_one("#status", Static).render())

    asyncio.run(exercise())


def test_tui_compact_layout_keeps_review_run_and_param_form_reachable() -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test(size=(80, 50)) as pilot:
            await pilot.pause()
            app.on_resize(SimpleNamespace(size=SimpleNamespace(width=80, height=50)))
            assert app.has_class("compact")
            search = app.query_one("#search", Input)
            search.value = "unpac"
            app._populate_capabilities(search.value)
            app.selected_cap = "unpac-the-hash"
            app._refresh_param_form()
            app.query_one("#domain", Input).value = "corp.test"
            app.query_one("#dc_ip", Input).value = "192.0.2.10"
            app._review_run()
            for selector in ("#review-btn", "#run-btn", "#param-form", "#search"):
                assert app.query_one(selector).display
            assert "unpac-the-hash" in str(app.query_one("#param-title", Static).render())
            assert "Execution review" in str(app.query_one("#review-panel", Static).render())
            # Wide again clears compact.
            app.on_resize(SimpleNamespace(size=SimpleNamespace(width=140, height=40)))
            assert not app.has_class("compact")

    asyncio.run(exercise())


def test_tui_engagement_dashboard_reflects_target_review_and_session_state(tmp_path) -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            dashboard = app.query_one("#engagement-dashboard", Static)
            assert "Awaiting target details" in str(dashboard.render())

            app.query_one("#domain", Input).value = "corp.test"
            app.query_one("#dc_ip", Input).value = "192.0.2.10"
            app.query_one("#scope", Input).value = "domain"
            app.selected_cap = "ldap-enum"
            app._update_engagement_dashboard()
            rendered = str(dashboard.render())
            assert "corp.test @ 192.0.2.10" in rendered
            assert "Scope: domain" in rendered
            assert "Read-only capability selected" in rendered
            assert "Ready to review" in rendered

            app._last_session = tmp_path
            app._update_engagement_dashboard()
            assert "Last session ready" in str(dashboard.render())

    asyncio.run(exercise())


def test_tui_pins_capabilities_and_restores_non_secret_target(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(user_config, "config_path", lambda: tmp_path / "config.json")

    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            app.selected_cap = "ldap-enum"
            app._refresh_pin_button()
            app._toggle_selected_favorite()
            assert "Unpin" in str(app.query_one("#pin-selected-btn", tui_app.Button).label)

            user_config.record_recent_target("corp.test", "192.0.2.10", "domain")
            app._restore_latest_target()
            assert app.query_one("#domain", Input).value == "corp.test"
            assert app.query_one("#dc_ip", Input).value == "192.0.2.10"
            assert app.query_one("#scope", Input).value == "domain"
            assert "password" not in (tmp_path / "config.json").read_text(encoding="utf-8").lower()

    asyncio.run(exercise())


def test_tui_resume_recovers_from_invalid_saved_wizard_step(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(user_config, "config_path", lambda: tmp_path / "config.json")
    (tmp_path / "config.json").write_text(
        json.dumps(
            {
                "ui.wizard_state": {
                    "domain": "corp.test",
                    "dc_ip": "192.0.2.10",
                    "selected_cap": "ldap-enum",
                    "step": "corrupted",
                }
            }
        ),
        encoding="utf-8",
    )

    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            notices = Mock()
            app.notify = notices  # type: ignore[method-assign]
            app._resume_wizard()
            assert app._wizard_step == 0
            assert app.query_one("#domain", Input).value == "corp.test"
            assert any("invalid" in str(call.args[0]).lower() for call in notices.call_args_list)

    asyncio.run(exercise())


def test_tui_refresh_action_preserves_a_populated_capability_list() -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            before = len(app.query_one("#cap-list", ListView))
            await pilot.press("l")
            await pilot.pause()
            assert len(app.query_one("#cap-list", ListView)) == before

    asyncio.run(exercise())


def test_tui_selects_capabilities_and_validates_run_requirements() -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            notifications = Mock()
            app.notify = notifications  # type: ignore[method-assign]

            first_item = app.query_one("#cap-list", ListView).children[0]
            app.on_list_view_selected(SimpleNamespace(item=first_item))  # type: ignore[arg-type]
            assert app.selected_cap == first_item.cap_id

            app.selected_cap = None
            app._start_run()
            assert notifications.call_args.kwargs["severity"] == "warning"
            assert "Select a capability" in notifications.call_args.args[0]

            app.selected_cap = "ldap-enum"
            app._start_run()
            assert notifications.call_args.kwargs["severity"] == "error"
            assert "Domain and DC IP" in notifications.call_args.args[0]

            app._capability_running = True
            app._start_run()
            assert notifications.call_args.kwargs["severity"] == "warning"
            assert notifications.call_args.args[0] == "Already running"

    asyncio.run(exercise())


def test_tui_search_review_and_dry_run_are_available() -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            all_count = len(app.query_one("#cap-list", ListView))
            app.query_one("#search", Input).value = "ldap-enum"
            await pilot.pause()
            assert len(app.query_one("#cap-list", ListView)) < all_count
            item = app.query_one("#cap-list", ListView).children[0]
            app.on_list_view_selected(SimpleNamespace(item=item))  # type: ignore[arg-type]
            app.query_one("#domain", Input).value = "corp.test"
            app.query_one("#dc_ip", Input).value = "192.0.2.10"
            app._review_run()
            assert "Execution review" in str(app.query_one("#review-panel", Static).render())
            app._dry_run()
            assert any("DRY RUN" in line for line in app._log_lines)

    asyncio.run(exercise())


def test_tui_beginner_mode_and_form_reset_are_reversible() -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            app.query_one("#domain", Input).value = "corp.test"
            app.query_one("#dc_ip", Input).value = "192.0.2.10"
            app._reset_form()
            assert app.query_one("#domain", Input).value == ""
            assert app.query_one("#undo-reset-btn", tui_app.Button).disabled is False
            app._undo_form_reset()
            assert app.query_one("#domain", Input).value == "corp.test"
            app._apply_beginner_mode(True)
            assert app.query_one("#scope", Input).display is False

    asyncio.run(exercise())


def test_tui_green_only_switch_filters_capability_list() -> None:
    async def exercise() -> None:
        from adaf_attack.core.novice import safety_summary
        from adaf_attack.core.ux import group_capabilities_by_phase, phase_label

        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            app.on_switch_changed(
                SimpleNamespace(switch=SimpleNamespace(id="green-only"), value=True)
            )
            await pilot.pause()
            assert app._green_only is True
            rendered_ids = [
                str(item.cap_id) for item in app.query_one("#cap-list", ListView).children
            ]
            expected_ids = [
                cap.id
                for group in group_capabilities_by_phase().values()
                for cap in group
                if safety_summary(cap)["level"] == "GREEN"
            ]
            assert expected_ids, "expected at least one offline-safe capability"
            assert rendered_ids == expected_ids
            rendered_headers = [
                str(item.phase_header)
                for item in app.query_one("#cap-list", ListView).children
                if item.phase_header
            ]
            expected_headers = []
            for phase, group in group_capabilities_by_phase().items():
                green = [cap for cap in group if safety_summary(cap)["level"] == "GREEN"]
                if green:
                    expected_headers.append(f"{phase_label(phase)} ({len(green)})")
            assert rendered_headers == expected_headers
            app.on_switch_changed(
                SimpleNamespace(switch=SimpleNamespace(id="green-only"), value=False)
            )
            await pilot.pause()
            assert app._green_only is False

    asyncio.run(exercise())


def test_tui_quickstart_is_idempotent_for_existing_demo_session(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "quickstart"
    monkeypatch.setattr(tui_app, "default_workspace_dir", lambda: workspace)

    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app._quickstart() is True
            first = app._last_session
            assert first == workspace / "demo-session"
            assert first is not None and first.is_dir()
            assert app._quickstart() is True
            assert app._last_session == first
            assert not (workspace / "quickstart" / "demo-session").exists()

    asyncio.run(exercise())


def test_tui_command_findings_and_standard_recommendations(tmp_path) -> None:
    """Cover operator-facing guidance paths using the in-process Textual pilot."""

    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            app.notify = Mock()  # type: ignore[method-assign]
            app.selected_cap = "ldap-enum"
            app._show_command_only()
            assert "Command only" in str(app.query_one("#review-panel", Static).render())
            app.action_undo_form_reset()
            app.on_switch_changed(
                SimpleNamespace(switch=SimpleNamespace(id="beginner-mode"), value=True)
            )
            app._last_session = None
            app._explain_findings()
            app._last_session = tmp_path
            (tmp_path / "findings.json").write_text(
                '{"findings": [{"type": "ldap"}]}', encoding="utf-8"
            )
            app._explain_findings()
            assert "Finding explanations" in str(app.query_one("#session-panel", Static).render())
            app._safe_mode = False
            app._show_next_actions("ldap-enum")
            assert "Suggested next" in str(app.query_one("#review-panel", Static).render())

    asyncio.run(exercise())


def test_tui_controls_validation_sessions_and_findings(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise local TUI controls without contacting a target."""

    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            notices = Mock()
            app.notify = notices  # type: ignore[method-assign]
            domain = app.query_one("#domain", Input)
            dc_ip = app.query_one("#dc_ip", Input)
            hashes = app.query_one("#hashes", Input)
            creds_file = app.query_one("#creds_file", Input)

            assert app._validate_target() is None
            domain.value = "corp.test"
            assert app._validate_target() is None
            dc_ip.value = "bad host"
            assert app._validate_target() is None
            dc_ip.value = "192.0.2.10"
            hashes.value = "not-a-hash"
            assert app._validate_target() is None
            hashes.value = ""
            creds_file.value = str(tmp_path / "missing.json")
            assert app._validate_target() is None
            creds_file.value = ""
            assert app._validate_target() == ("corp.test", "192.0.2.10")

            app._toggle_password()
            assert app.query_one("#password", Input).password is False
            app.on_input_changed(SimpleNamespace(input=domain, value="corp.test"))
            app.on_input_changed(
                SimpleNamespace(input=app.query_one("#log-filter", Input), value="beta")
            )
            assert app._selected() is None
            app._update_help()
            app.action_list_caps()
            app.action_run_selected()
            app.action_review_run()
            app.action_dry_run()
            app.action_show_sessions()
            app.action_toggle_password()
            app._review_run()
            app._dry_run()
            app._quickstart()
            review_text = str(app.query_one("#review-panel", Static).render())
            assert "quickstart" in review_text.lower()
            assert "adaf-attack guide" in review_text
            app._show_findings()
            findings_text = str(app.query_one("#session-panel", Static).render()).lower()
            # Offline Quickstart materializes a demo session; findings should bind to it.
            assert "findings dashboard" in findings_text or "select a session" in findings_text
            app._cancel()
            app._show_log("alpha\nbeta")
            app.query_one("#log-filter", Input).value = "beta"
            app._refresh_log()

            workspace = tmp_path / "workspace"
            session = workspace / "one"
            session.mkdir(parents=True)
            (workspace / "not-a-session").mkdir()
            (session / "session.json").write_text(
                json.dumps({"session_id": "one", "created_at": "2026-01-01T00:00:00Z"}),
                encoding="utf-8",
            )
            monkeypatch.setattr(tui_app, "default_workspace_dir", lambda: workspace)
            app._show_sessions()
            assert "one" in str(app.query_one("#session-panel", Static).render())

            (session / "interesting.json").write_text(
                json.dumps({"top_paths": [{"path": ["a@corp", "b@corp"]}]}), encoding="utf-8"
            )
            (session / "graph.json").write_text(
                json.dumps({"summary": {"nodes": 2, "edges": 1}}), encoding="utf-8"
            )
            (session / "findings.json").write_text(
                json.dumps({"findings": [{"severity": "high"}, "bad"]}), encoding="utf-8"
            )
            app._last_session = session
            app._show_findings()
            assert "Findings dashboard" in str(app.query_one("#session-panel", Static).render())
            assert app._read_json(tmp_path / "missing.json") == {}
            (tmp_path / "array.json").write_text("[]", encoding="utf-8")
            assert app._read_json(tmp_path / "array.json") == {}
            app.on_button_pressed(SimpleNamespace(button=SimpleNamespace(id="quickstart-btn")))
            app.on_button_pressed(SimpleNamespace(button=SimpleNamespace(id="unknown")))

            app.selected_cap = "ldap-enum"
            app._review_run()
            app._dry_run()
            domain.value = ""
            app._review_run()
            domain.value = "corp.test"
            app.selected_cap = "shadow-creds"
            app.query_one("#force", tui_app.Switch).value = False
            app._review_run()
            app.selected_cap = "ldap-enum"
            app.query_one("#start", Input).value = "user@corp.test"

            def successful_run(*args, **kwargs):
                app._cancel_requested.set()
                kwargs["log"]("runner message")
                kwargs["log"]("connect to target")
                kwargs["log"]("resolved graph edges")
                return {
                    "session_path": str(session),
                    "session_id": "one",
                    "graph_summary": {"nodes": 2, "edges": 1},
                }

            monkeypatch.setattr(tui_app, "execute_capability", successful_run)
            app._start_run()
            await _wait_for(pilot, lambda: app._capability_running is False)
            assert app._capability_running is False
            monkeypatch.setattr(
                tui_app,
                "execute_capability",
                lambda *args, **kwargs: (_ for _ in ()).throw(tui_app.RunError("offline failure")),
            )
            app._start_run()
            await _wait_for(pilot, lambda: app._capability_running is False)
            app._capability_running = True
            app._cancel()
            monkeypatch.setattr(app, "copy_to_clipboard", lambda text: None)
            app._copy_findings()
            monkeypatch.setattr(
                app,
                "copy_to_clipboard",
                lambda text: (_ for _ in ()).throw(RuntimeError("clipboard")),
            )
            app._copy_findings()

    asyncio.run(exercise())

    monkeypatch.setattr(ADAFAttackApp, "run", lambda self: None)
    tui_app.run_tui()


def test_tui_operator_safety_and_profile_controls(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cover the review gate, profiles, status affordances, and follow-on UI paths."""

    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            notices = Mock()
            app.notify = notices  # type: ignore[method-assign]
            monkeypatch.setattr(tui_app, "default_workspace_dir", lambda: tmp_path / "workspace")
            monkeypatch.setattr(tui_app, "active_opsec", lambda: "stealth")
            monkeypatch.setattr(tui_app, "list_profiles", lambda: [{"name": "engagement"}])
            monkeypatch.setattr(tui_app, "load_user_config", dict)
            saved_config: list[dict[str, object]] = []
            monkeypatch.setattr(
                tui_app, "save_user_config", lambda value: saved_config.append(value)
            )

            app._acknowledge_review()
            workspace = tmp_path / "workspace"
            session = workspace / "session-a"
            session.mkdir(parents=True)
            (session / "session.json").write_text('{"session_id": "session-a"}', encoding="utf-8")
            (session / "findings.json").write_text(
                '{"findings": [{"severity": "high"}]}', encoding="utf-8"
            )
            app._show_sessions()
            assert "H:1" in str(app.query_one("#session-panel", Static).render())

            profile_name = app.query_one("#profile-name", Input)
            profile_name.value = "missing"
            monkeypatch.setattr(tui_app, "get_profile", lambda name: None)
            app._refresh_profile_hint()
            app._apply_profile()

            profile = {
                "domain": "corp.test",
                "dc_ip": "192.0.2.10",
                "username": "operator",
                "scope": "domain",
                "kerberos": True,
                "ldaps": True,
            }
            profile_name.value = "engagement"
            monkeypatch.setattr(tui_app, "get_profile", lambda name: profile)
            app._apply_profile()
            assert app.query_one("#domain", Input).value == "corp.test"
            assert app.query_one("#kerberos", tui_app.Switch).value is True

            profile_name.value = ""
            app._save_profile()
            profile_name.value = "engagement"
            stored: list[tuple[str, dict[str, object]]] = []
            monkeypatch.setattr(
                tui_app, "set_profile", lambda name, value: stored.append((name, value))
            )
            app._save_profile(make_default=True)
            assert stored and saved_config == [{"profile.default": "engagement"}]
            monkeypatch.setattr(
                tui_app,
                "set_profile",
                lambda name, value: (_ for _ in ()).throw(ValueError("bad profile")),
            )
            app._save_profile()

            for widget_id, value in (
                ("password", "secret"),
                ("hashes", "0" * 32),
                ("aes_key", "a" * 64),
                ("ccache", "ticket.ccache"),
            ):
                widget = app.query_one(f"#{widget_id}", Input)
                widget.value = value
                app.on_input_changed(SimpleNamespace(input=widget, value=value))
            assert "values hidden" in str(app.query_one("#credential-strip", Static).render())

            app.selected_cap = "shadow-creds"
            app._review_run()
            force = app.query_one("#force", tui_app.Switch)
            force.value = True
            app.on_switch_changed(SimpleNamespace(switch=force))
            app._review_run()
            app.on_checkbox_changed(SimpleNamespace())
            app._acknowledge_review()
            for item in ("scope", "auth", "force", "opsec", "rollback"):
                app.query_one(f"#check-{item}", tui_app.Checkbox).value = True
            app._acknowledge_review()
            assert app.query_one("#run-btn", tui_app.Button).disabled is False
            app._reviewed_cap = None
            app._start_run()

            app.action_focus_search()
            app._log_lines = []
            app.action_jump_to_error()
            app._log_lines = ["info", "ERROR: broken"]
            app.action_jump_to_error()
            app.selected_cap = None
            app._copy_ready_command()
            app.selected_cap = "ldap-enum"
            monkeypatch.setattr(app, "copy_to_clipboard", lambda text: None)
            app._copy_ready_command()
            monkeypatch.setattr(
                app,
                "copy_to_clipboard",
                lambda text: (_ for _ in ()).throw(RuntimeError("clipboard")),
            )
            app._copy_ready_command()
            assert "Select and copy this shell-safe command manually" in str(
                app.query_one("#review-panel", Static).render()
            )

            app.selected_cap = None
            app._update_progress()
            app.selected_cap = "kerberoast"
            app._active_stage = "harvest"
            app._update_progress()
            assert "harvest" in str(app.query_one("#progress", Static).render())
            app._show_next_actions("missing")
            app._show_next_actions("ldap-enum")
            assert "Suggested next" in str(app.query_one("#review-panel", Static).render())

    asyncio.run(exercise())


def test_tui_guided_workflow_templates_readiness_and_pause_controls() -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app._wizard_step == 0
            assert "Readiness:" in str(app.query_one("#readiness", Static).render())

            app.query_one("#domain", Input).value = "corp.test"
            app.query_one("#dc_ip", Input).value = "192.0.2.10"
            app.on_button_pressed(SimpleNamespace(button=SimpleNamespace(id="template-adcs")))
            assert app.selected_cap == "adcs-enum"
            assert app._wizard_step == 0

            app._wizard_next()
            assert app._wizard_step == 1
            app._wizard_next()
            assert app._wizard_step == 2
            app._show_run_summary()
            assert "Estimated duration" in str(app.query_one("#summary-panel", Static).render())

            app._capability_running = True
            app._toggle_pause()
            assert app._pause_requested.is_set() is True
            app._toggle_pause()
            assert app._pause_requested.is_set() is False

    asyncio.run(exercise())


def test_tui_guided_workflow_persistence_recommendations_and_exports(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            app.notify = Mock()  # type: ignore[method-assign]
            app._workflow = None
            app._refresh_workflow_panel()
            monkeypatch.setattr(tui_app, "default_workspace_dir", lambda: tmp_path / "workflow")
            app._ensure_workflow_started()
            assert app._workflow is not None
            # Run must not silently complete authorize-scope (CLI guide stays authoritative).
            assert "scope-authorized" not in app._workflow.state.completed_steps
            missing = tmp_path / "missing-session"
            app._workflow = None
            app._ingest_session_findings(missing)
            app._workflow = WorkflowEngine(tmp_path / "workflow")
            bad = tmp_path / "bad-session"
            bad.mkdir()
            (bad / "findings.json").write_text("not-json", encoding="utf-8")
            app._ingest_session_findings(bad)
            (bad / "findings.json").write_text('{"findings": {}}', encoding="utf-8")
            app._ingest_session_findings(bad)
            (bad / "findings.json").write_text(
                '[{"id": "F-TUI", "title": "TUI finding", "severity": "low"}, {"id": "", "title": "skip"}]',
                encoding="utf-8",
            )
            app._ingest_session_findings(bad)
            assert "F-TUI" in app._workflow.state.findings
            saved: list[dict[str, object]] = []
            monkeypatch.setattr(tui_app, "save_user_config", lambda value: saved.append(value))
            monkeypatch.setattr(
                tui_app,
                "load_user_config",
                lambda: {
                    "ui.wizard_state": {
                        "step": 2,
                        "selected_cap": "ldap-enum",
                        "domain": "corp.test",
                        "dc_ip": "192.0.2.10",
                        "username": "operator",
                        "scope": "domain",
                    }
                },
            )
            app.selected_cap = "ldap-enum"
            app._save_wizard_state()
            assert saved
            app._load_wizard_resume()
            app._resume_wizard()
            assert app.selected_cap == "ldap-enum"
            monkeypatch.setattr(tui_app, "load_user_config", lambda: {"ui.wizard_state": "invalid"})
            app._resume_wizard()
            monkeypatch.setattr(tui_app, "load_user_config", lambda: {"ui.wizard_state": {}})

            app.query_one("#domain", Input).value = ""
            app._validate_target_inline()
            app.query_one("#domain", Input).value = "corp.test"
            app.query_one("#dc_ip", Input).value = "192.0.2.10"
            app._validate_target_inline()
            app._show_recommendations()
            app.selected_cap = None
            app._show_recommendations()
            app._update_readiness()
            app.selected_cap = "ldap-enum"
            app._reviewed_cap = "ldap-enum"
            app._update_readiness()
            app._show_run_summary()
            monkeypatch.setattr(
                tui_app, "default_workspace_dir", lambda: tmp_path / "missing" / "nested"
            )
            app._update_status()
            app.selected_cap = None
            app._show_run_summary()
            app._wizard_step = 0
            app.query_one("#domain", Input).value = ""
            app._wizard_next()
            app._wizard_step = 2
            app._wizard_next()
            app.query_one("#domain", Input).value = "corp.test"
            app.query_one("#dc_ip", Input).value = "192.0.2.10"
            app.selected_cap = "shadow-creds"
            app._wizard_step = 3
            app._wizard_next()

            app._toggle_pause()
            app._capability_running = True
            app._toggle_pause()
            app._toggle_pause()
            app._wizard_step = 5
            app._wizard_next()
            app._wizard_step = 2
            app._capability_running = False
            app._wizard_back()
            app.query_one("#domain", Input).value = "corp.test"
            app.query_one("#dc_ip", Input).value = "192.0.2.10"
            app.selected_cap = "ldap-enum"
            app._wizard_step = 2
            app._wizard_next()
            app._wizard_step = 3
            app._wizard_next()
            app._wizard_step = 4
            app._capability_running = True
            app._wizard_next()
            app._wizard_start_over()
            app._capability_running = False
            app._wizard_start_over()

            monkeypatch.setattr(tui_app.capability_registry, "get", lambda _value: None)
            app._apply_template("recon")
            monkeypatch.undo()

            app._last_session = None
            app._create_reports()
            app._package_evidence()
            session = tmp_path / "session"
            session.mkdir()
            app._last_session = session
            (session / "findings.json").write_text('{"findings": []}', encoding="utf-8")
            (session / "cleanup.json").write_text("[]", encoding="utf-8")
            from adaf_attack.core import reporting

            monkeypatch.setattr(reporting, "_pdf", lambda *_args: True)
            reporting.generate_report_bundle(session)
            monkeypatch.setattr(
                tui_app,
                "generate_report_bundle",
                lambda _session: {"executive_html": "report.html"},
            )
            monkeypatch.setattr(
                tui_app,
                "package_evidence",
                lambda _session, _destination: {
                    "archive": "evidence.zip",
                    "file_count": 1,
                    "profile": "client",
                },
            )
            app._create_reports()
            app._package_evidence()
            monkeypatch.setattr(
                tui_app,
                "generate_report_bundle",
                lambda _session: (_ for _ in ()).throw(RuntimeError("report")),
            )
            monkeypatch.setattr(
                tui_app,
                "package_evidence",
                lambda _session, _destination: (_ for _ in ()).throw(RuntimeError("package")),
            )
            app._create_reports()
            app._package_evidence()

            monkeypatch.setattr(
                tui_app, "save_user_config", lambda _value: (_ for _ in ()).throw(OSError())
            )
            app._save_wizard_state()
            monkeypatch.setattr(
                tui_app, "load_user_config", lambda: (_ for _ in ()).throw(OSError())
            )
            app._load_wizard_resume()
            app._resume_wizard()

            app._capability_running = False
            app.selected_cap = "ldap-enum"
            app.query_one("#domain", Input).value = "corp.test"
            app.query_one("#dc_ip", Input).value = "192.0.2.10"

            def paused_runner(*_args: object, **kwargs: object) -> dict[str, object]:
                app._pause_requested.set()
                threading.Timer(0.05, app._pause_requested.clear).start()
                kwargs["log"]("pause boundary")  # type: ignore[index]
                return {"session_path": str(session), "session_id": "test", "graph_summary": {}}

            monkeypatch.setattr(tui_app, "execute_capability", paused_runner)
            app._start_run()
            await _wait_for(pilot, lambda: app._capability_running is False)
            monkeypatch.setattr(
                app,
                "_ensure_workflow_started",
                lambda: (_ for _ in ()).throw(RuntimeError("workflow unavailable")),
            )
            monkeypatch.setattr(
                tui_app,
                "execute_capability",
                lambda *_args, **_kwargs: (_ for _ in ()).throw(tui_app.RunError("runner")),
            )
            app._start_run()
            await _wait_for(pilot, lambda: app._capability_running is False)
            assert any("When lost: adaf-attack guide" in line for line in app._log_lines)

    asyncio.run(exercise())


def test_tui_journey_uses_doctor_for_install_blocked(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TUI Home Cmd must match CLI guide when doctor reports blockers."""
    monkeypatch.setattr(tui_app, "default_workspace_dir", lambda: tmp_path)

    def blocked_doctor(profile: str, **_kwargs: object) -> dict[str, object]:
        assert profile == "user-readiness"
        return {
            "ok": False,
            "ready": False,
            "checks": [
                {
                    "id": "packaged-demo",
                    "status": "error",
                    "detail": "missing",
                    "remediation": "Reinstall the release artifact.",
                    "severity": "blocking",
                }
            ],
        }

    monkeypatch.setattr("adaf_attack.cli._doctor_payload", blocked_doctor)
    app = ADAFAttackApp()
    journey = app._journey()
    assert journey["stage"] == "install-blocked"
    assert "doctor" in journey["primary_action"]["suggested_command"]


def test_tui_doctor_cache_refreshes_after_ttl(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tui_app, "default_workspace_dir", lambda: tmp_path)
    clock = iter((1.0, 2.0, 12.0))
    calls: list[str] = []

    def doctor(profile: str, **_kwargs: object) -> dict[str, object]:
        calls.append(profile)
        return {"ok": True, "ready": True, "checks": []}

    import adaf_attack.cli as cli

    monkeypatch.setattr(cli, "_doctor_payload", doctor)
    monkeypatch.setattr(tui_app.time, "monotonic", lambda: next(clock))
    app = ADAFAttackApp()
    app._journey()
    app._journey()
    app._journey()
    assert calls == ["user-readiness", "user-readiness"]


@pytest.mark.parametrize(
    ("doctor", "with_demo", "authorize", "complete", "expected_stage"),
    [
        (
            {
                "ok": False,
                "checks": [
                    {
                        "id": "packaged-demo",
                        "status": "error",
                        "value": "missing",
                        "remediation": "Reinstall the release artifact.",
                        "repair_command": "python -m pip check",
                    }
                ],
            },
            False,
            False,
            False,
            "install-blocked",
        ),
        ({"ok": True, "checks": []}, False, False, False, "first-success"),
        ({"ok": True, "checks": []}, True, False, False, "orient"),
        ({"ok": True, "checks": []}, True, True, False, "discover"),
        ({"ok": True, "checks": []}, True, True, True, "complete"),
    ],
)
def test_tui_journey_exactly_matches_shared_snapshot_across_states(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    doctor: dict[str, object],
    with_demo: bool,
    authorize: bool,
    complete: bool,
    expected_stage: str,
) -> None:
    from adaf_attack.core.journey import snapshot
    from adaf_attack.demo import materialize_demo_session

    workspace = tmp_path / expected_stage
    session = workspace / "demo-session"
    if with_demo:
        materialize_demo_session(session)
    if authorize:
        engine = WorkflowEngine(workspace)
        engine.start(actor="test")
        engine.complete_action("authorize-scope", actor="test")
        if complete:
            engine.complete_action("run-discovery", actor="test")
            engine.close(actor="test")
    monkeypatch.setattr("adaf_attack.cli._doctor_payload", lambda profile: doctor)
    app = ADAFAttackApp(workspace=workspace)
    app._last_session = session if with_demo else None
    expected = snapshot(
        workspace=workspace,
        session=session if with_demo else None,
        doctor=doctor,
    )
    actual = app._journey()
    assert actual["stage"] == expected_stage
    assert actual["stage"] == expected["stage"]
    assert actual["suggested_command"] == expected["suggested_command"]
    assert (
        actual["primary_action"]["suggested_command"]
        == expected["primary_action"]["suggested_command"]
    )
    assert actual["recovery_command"] == expected["recovery_command"]
    if expected_stage == "install-blocked":
        assert actual["suggested_command"] == "python -m pip check"


def test_tui_journey_surfaces_share_evidence_command_and_recovery(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "adaf_attack.cli._doctor_payload", lambda profile: {"ok": True, "checks": []}
    )

    async def exercise() -> None:
        app = ADAFAttackApp(workspace=tmp_path)
        async with app.run_test():
            journey = app._journey()
            command = journey["suggested_command"]
            recovery = journey["recovery_command"]
            app._show_home()
            home = str(app.query_one("#first-launch-panel", Static).render())
            app._show_what_next()
            what_next = str(app.query_one("#recommendations-panel", Static).render())
            app._set_wizard_step(2)
            wizard = str(app.query_one("#wizard-guide", Static).render())
            app._refresh_workflow_panel()
            workflow = str(app.query_one("#workflow-state-panel", Static).render())
            for surface in (home, what_next, wizard, workflow):
                assert command in surface
                assert recovery in surface
                assert "Evidence:" in surface

    asyncio.run(exercise())


def test_tui_corrupt_workflow_state_is_actionable(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "workflow-state.json").write_text("not-json", encoding="utf-8")
    monkeypatch.setattr(
        "adaf_attack.cli._doctor_payload", lambda profile: {"ok": True, "checks": []}
    )

    async def exercise() -> None:
        app = ADAFAttackApp(workspace=tmp_path)
        async with app.run_test():
            panel = str(app.query_one("#workflow-state-panel", Static).render())
            assert "Workflow: unavailable" in panel
            assert "support-bundle" in panel
            assert "If this fails: adaf-attack guide" in panel

    asyncio.run(exercise())
