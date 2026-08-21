"""Coverage gate tests for remaining branches in the ADAF-ATTACK TUI."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from textual.widgets import Input

from adaf_attack.tui import app as tui_app
from adaf_attack.tui.app import ADAFAttackApp, CapabilityItem


class _PrefilledDomainApp(ADAFAttackApp):
    """Mounts with a target already entered so the first-run hint is skipped."""

    def on_mount(self) -> None:
        self.query_one("#domain", Input).value = "corp.test"
        super().on_mount()


def _patch_query_one(app: ADAFAttackApp, failing_ids: set[str]) -> None:
    original = ADAFAttackApp.query_one.__get__(app)

    def wrapper(selector: str, *args: object, **kwargs: object):
        if selector in failing_ids:
            raise RuntimeError(f"missing widget {selector}")
        return original(selector, *args, **kwargs)  # type: ignore[arg-type]

    app.query_one = wrapper  # type: ignore[method-assign]


def _unpatch_query_one(app: ADAFAttackApp) -> None:
    app.query_one = ADAFAttackApp.query_one.__get__(app)  # type: ignore[method-assign]


def test_tui_mount_with_prefilled_domain_skips_first_run_hint() -> None:
    async def exercise() -> None:
        app = _PrefilledDomainApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.query_one("#domain", Input).value == "corp.test"

    asyncio.run(exercise())


def test_tui_green_only_switch_and_selection_branches() -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            app.notify = Mock()  # type: ignore[method-assign]

            app.on_switch_changed(
                SimpleNamespace(switch=SimpleNamespace(id="green-only"), value=True)
            )
            assert app._green_only is True
            app.on_switch_changed(
                SimpleNamespace(switch=SimpleNamespace(id="green-only"), value=False)
            )
            app.on_switch_changed(
                SimpleNamespace(switch=SimpleNamespace(id="unknown-switch"), value=True)
            )

            app.on_list_view_selected(SimpleNamespace(item=object()))

            app._wizard_step = 2
            item = CapabilityItem(tui_app.capability_registry.get("ldap-enum"))
            app.selected_cap = None
            app.on_list_view_selected(SimpleNamespace(item=item))
            assert app.selected_cap == "ldap-enum"
            assert app._wizard_step == 2

            app._wizard_step = 0
            app._capability_running = False
            app._wizard_back()

            app._apply_beginner_mode(False)
            assert app._safe_mode is False
            await pilot.pause()

    asyncio.run(exercise())


def test_tui_first_launch_panel_error_paths() -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test():
            app.notify = Mock()  # type: ignore[method-assign]
            _patch_query_one(app, {"#domain"})
            app._refresh_first_launch_panel()
            _patch_query_one(app, {"#first-launch-panel"})
            app._refresh_first_launch_panel()
            _unpatch_query_one(app)

    asyncio.run(exercise())


def test_tui_workflow_checkpoint_oserror_is_logged(tmp_path) -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test():
            app.notify = Mock()  # type: ignore[method-assign]
            session = tmp_path / "session"
            session.mkdir()
            (session / "findings.json").write_text(
                json.dumps([{"id": "F-1", "title": "Finding", "severity": "low"}]),
                encoding="utf-8",
            )
            workflow = Mock()
            workflow.ingest_finding = Mock()
            workflow.complete_step = Mock(side_effect=OSError("read-only home"))
            app._workflow = workflow
            app._ingest_session_findings(session)
            workflow.complete_step.assert_called_once()

    asyncio.run(exercise())


def test_tui_pin_restore_profile_and_error_paths(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test():
            app.notify = Mock()  # type: ignore[method-assign]

            app.selected_cap = None
            app._toggle_selected_favorite()

            app.selected_cap = "ldap-enum"
            monkeypatch.setattr(
                tui_app,
                "set_favorite_capability",
                lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("denied")),
            )
            app._toggle_selected_favorite()
            monkeypatch.undo()

            monkeypatch.setattr(tui_app, "recent_targets", lambda limit=5: [])
            app._restore_latest_target()
            monkeypatch.undo()

            _patch_query_one(app, {"#engagement-dashboard"})
            app._update_engagement_dashboard()
            _unpatch_query_one(app)

            monkeypatch.setattr(tui_app, "get_profile", lambda _name: {"domain": "corp.test"})
            app.query_one("#profile-name", Input).value = "staging"
            app._apply_profile()
            monkeypatch.undo()

            saved: dict[str, dict[str, object]] = {}
            monkeypatch.setattr(
                tui_app,
                "set_profile",
                lambda name, values: saved.setdefault(name, values),
            )
            app.query_one("#profile-name", Input).value = "staging"
            app._save_profile(make_default=False)
            assert "staging" in saved

            app._log_lines = ["plain operator line"]
            app.action_jump_to_error()

            missing = tmp_path / "missing-workspace"
            monkeypatch.setattr(tui_app, "default_workspace_dir", lambda: missing)
            app._show_sessions()

            workspace = tmp_path / "workspace"
            odd = workspace / "odd-session"
            odd.mkdir(parents=True)
            (odd / "session.json").write_text("{}", encoding="utf-8")
            (odd / "findings.json").write_text('{"findings": 42}', encoding="utf-8")
            rich = workspace / "rich-session"
            rich.mkdir()
            (rich / "session.json").write_text("{}", encoding="utf-8")
            (rich / "findings.json").write_text(
                json.dumps(
                    {
                        "findings": [
                            {"id": "F-1", "severity": "high"},
                            "not-a-dict",
                            {"id": "F-2", "severity": "low"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            monkeypatch.setattr(tui_app, "default_workspace_dir", lambda: workspace)
            app._show_sessions()
            monkeypatch.undo()

            app._safe_mode = False
            monkeypatch.setattr(
                tui_app, "suggested_next_actions", lambda _cap: ["no-such-capability"]
            )
            app._show_next_actions("ldap-enum")
            app._safe_mode = True
            app._show_next_actions("ldap-enum")
            monkeypatch.undo()

    asyncio.run(exercise())


def test_tui_session_panels_cockpit_timeline_copilot_and_next(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test():
            app.notify = Mock()  # type: ignore[method-assign]

            app._last_session = None
            app._show_cockpit()
            app._show_timeline()
            app._show_copilot()
            app._explain_selected()

            session = tmp_path / "session"
            session.mkdir()
            app._last_session = session
            monkeypatch.setattr(
                tui_app,
                "evidence_cockpit",
                lambda _session: {"priority_focus": [], "dashboard": {"finding_count": 0}},
            )
            monkeypatch.setattr(
                tui_app,
                "session_timeline",
                lambda _session, limit=12: {
                    "events": [
                        {"time": None, "type": "run", "capability": None},
                        {"time": "2026-01-01", "type": "finding", "capability": "ldap-enum"},
                    ]
                },
            )
            monkeypatch.setattr(
                tui_app,
                "copilot_recommendations",
                lambda _session: {
                    "recommendations": [
                        {"action": "Review", "why": "check", "command": "adaf doctor"}
                    ]
                },
            )
            app._show_cockpit()
            app._show_timeline()
            app._show_copilot()

            app.selected_cap = "ldap-enum"
            app._explain_selected()
            app._show_what_next()
            app.selected_cap = None
            app._show_what_next()

    asyncio.run(exercise())
