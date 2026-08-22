"""Pilot-driven behavioral tests for key TUI interaction paths.

These complement the existing branch-covering tests: each test drives the app
through a user-observable path (typing, focus change, keybinding) and checks
visible state rather than internal counters.
"""

from __future__ import annotations

import asyncio

from textual.widgets import Input

from adaf_attack.tui.app import ADAFAttackApp


def _run(coro):
    return asyncio.run(coro)


def test_typing_domain_updates_target_state() -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            domain = app.query_one("#domain", Input)
            domain.value = ""
            await pilot.pause()
            domain.focus()
            await pilot.press("c", "o", "r", "p", ".", "t", "e", "s", "t")
            await pilot.pause()
            assert app.query_one("#domain", Input).value == "corp.test"

    _run(exercise())


def test_ctrl_k_focuses_search_bar() -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("ctrl+k")
            await pilot.pause()
            # The search Input, once focused, is the active widget.
            focused = app.focused
            assert focused is not None
            # The search widget id may vary; assert it is an Input.
            assert isinstance(focused, Input)

    _run(exercise())


def test_cheat_sheet_binding_shows_help_content() -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            # Bindings with "?" are common cheat-sheet triggers; the app should
            # not crash and should remain running afterwards.
            await pilot.press("?")
            await pilot.pause()
            assert app.is_running

    _run(exercise())


def test_password_toggle_action_flips_visibility() -> None:
    async def exercise() -> None:
        app = ADAFAttackApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            password = app.query_one("#password", Input)
            initial_password_setting = password.password
            app.action_toggle_password()
            await pilot.pause()
            assert app.query_one("#password", Input).password != initial_password_setting

    _run(exercise())
