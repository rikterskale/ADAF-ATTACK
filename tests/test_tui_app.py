"""Textual interaction tests for the ADAF-ATTACK TUI."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import Mock

from textual.widgets import Input, ListView, Static

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
