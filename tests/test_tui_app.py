"""Textual interaction tests for the ADAF-ATTACK TUI."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from textual.widgets import Input, ListView, Static

from adaf_attack.tui import app as tui_app
from adaf_attack.tui.app import ADAFAttackApp


def test_tui_starts_populates_capabilities_and_updates_status() -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            capabilities = app.query_one("#cap-list", ListView)
            assert len(capabilities) > 10
            app.query_one("#domain", Input).value = "corp.test"
            app.query_one("#dc_ip", Input).value = "192.0.2.10"
            app.selected_cap = "ldap-enum"
            app._update_status()
            assert "corp.test @ 192.0.2.10" in str(app.query_one("#status", Static).render())
            assert "ldap-enum" in str(app.query_one("#status", Static).render())

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
            assert "Quickstart" in str(app.query_one("#review-panel", Static).render())
            app._show_findings()
            assert (
                "select a session" in str(app.query_one("#session-panel", Static).render()).lower()
            )
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
            await asyncio.sleep(0.1)
            await pilot.pause()
            assert app._capability_running is False
            monkeypatch.setattr(
                tui_app,
                "execute_capability",
                lambda *args, **kwargs: (_ for _ in ()).throw(tui_app.RunError("offline failure")),
            )
            app._start_run()
            await asyncio.sleep(0.1)
            await pilot.pause()
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
            monkeypatch.setattr(tui_app, "list_profiles", lambda: [{"name": "lab"}])
            monkeypatch.setattr(tui_app, "load_user_config", lambda: {})
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
            profile_name.value = "lab"
            monkeypatch.setattr(tui_app, "get_profile", lambda name: profile)
            app._apply_profile()
            assert app.query_one("#domain", Input).value == "corp.test"
            assert app.query_one("#kerberos", tui_app.Switch).value is True

            profile_name.value = ""
            app._save_profile()
            profile_name.value = "lab"
            stored: list[tuple[str, dict[str, object]]] = []
            monkeypatch.setattr(
                tui_app, "set_profile", lambda name, value: stored.append((name, value))
            )
            app._save_profile(make_default=True)
            assert stored and saved_config == [{"profile.default": "lab"}]
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
